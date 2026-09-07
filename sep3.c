#include "sep3.h"

#include <string.h>

enum {
    SEP3_TYPE_OFFSET = 0,
    SEP3_TRANSACTION_ID_OFFSET = 1,
    SEP3_DATA_ID_OFFSET = 3,
    SEP3_PAYLOAD_OFFSET = 4,
    SEP3_CHECKSUM_SIZE = 2,
    SEP3_MIN_PACKET_SIZE = 6,
    SEP3_RESERVED_DATA_ID_START = 0xF0,
    SEP3_FRAMER_START = 0xD4,
    SEP3_FRAMER_END = 0x81,
    SEP3_FRAMER_MARK_MASK = 0x80,
    SEP3_TX_FREE = 0,
    SEP3_TX_QUEUED = 1,
    SEP3_TX_IN_FLIGHT = 2,
    SEP3_TX_PURPOSE_NONE = 0,
    SEP3_TX_PURPOSE_OUTGOING_REQUEST = 1,
    SEP3_TX_PURPOSE_INCOMING_ANSWER = 2,
    SEP3_TX_PURPOSE_UNACKNOWLEDGED = 3,
    SEP3_TX_PURPOSE_TRANSIENT_ANSWER = 4,
};

static uint16_t sep3__crc16(uint8_t const *data, uint16_t data_size)
{
    uint16_t crc = 0xFFFF;

    for (uint16_t i = 0; i < data_size; ++i) {
        crc ^= (uint16_t)data[i] << 8;
        for (uint8_t bit = 0; bit < 8; ++bit) {
            if (0 != (crc & 0x8000)) {
                crc = (uint16_t)((crc << 1) ^ 0x1021);
            } else {
                crc <<= 1;
            }
        }
    }

    return crc;
}

static TransactionId sep3__read_u16_le(uint8_t const *data)
{
    return (TransactionId)((TransactionId)data[0] | ((TransactionId)data[1] << 8));
}

static void sep3__write_u16_le(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
}

static bool sep3__is_packet_type(uint8_t type)
{
    switch (type) {
    case SEP3_PACKET_WRITE:
    case SEP3_PACKET_WRITE_NO_ANSWER:
    case SEP3_PACKET_READ:
    case SEP3_PACKET_WRITE_ANSWER:
    case SEP3_PACKET_READ_ANSWER:
    case SEP3_PACKET_APP_ERROR_ANSWER:
    case SEP3_PACKET_PROTO_ERROR_ANSWER:
        return true;
    default:
        return false;
    }
}

static int sep3__build_packet(
    uint8_t *packet,
    Sep3PacketType type,
    TransactionId transaction_id,
    DataId data_id,
    uint8_t const *payload,
    uint16_t payload_size,
    uint16_t *packet_size)
{
    uint16_t size = 0;
    uint16_t crc = 0;

    if ((NULL == packet) || (NULL == packet_size)) {
        return ER_INVAL;
    }
    if (payload_size > SEP3_MAX_PAYLOAD_SIZE) {
        return ER_OVERFLOW;
    }
    if ((0 != payload_size) && (NULL == payload)) {
        return ER_INVAL;
    }

    size = (uint16_t)(SEP3_MIN_PACKET_SIZE + payload_size);
    packet[SEP3_TYPE_OFFSET] = (uint8_t)type;
    sep3__write_u16_le(&packet[SEP3_TRANSACTION_ID_OFFSET], transaction_id);
    packet[SEP3_DATA_ID_OFFSET] = data_id;
    if (0 != payload_size) {
        memcpy(&packet[SEP3_PAYLOAD_OFFSET], payload, payload_size);
    }

    crc = sep3__crc16(packet, (uint16_t)(size - SEP3_CHECKSUM_SIZE));
    sep3__write_u16_le(&packet[size - SEP3_CHECKSUM_SIZE], crc);
    *packet_size = size;
    return 0;
}

static bool sep3__packet_crc_is_valid(uint8_t const *packet, uint16_t packet_size)
{
    uint16_t expected = 0;
    uint16_t actual = 0;

    if ((NULL == packet) || (packet_size < SEP3_MIN_PACKET_SIZE)) {
        return false;
    }

    expected = sep3__read_u16_le(&packet[packet_size - SEP3_CHECKSUM_SIZE]);
    actual = sep3__crc16(packet, (uint16_t)(packet_size - SEP3_CHECKSUM_SIZE));
    return expected == actual;
}

static bool sep3__framing_is_canonical(
    uint16_t encoded_size,
    uint8_t last_encoded_byte,
    uint16_t decoded_size)
{
    uint16_t expected_encoded_size = (uint16_t)(((uint32_t)decoded_size * 8U + 6U) / 7U);
    uint8_t remainder = (uint8_t)(decoded_size % 7U);

    if (encoded_size != expected_encoded_size) {
        return false;
    }
    if (0 != remainder) {
        uint8_t padding_mask = (uint8_t)((1U << (7U - remainder)) - 1U);
        if (0 != (last_encoded_byte & padding_mask)) {
            return false;
        }
    }
    return true;
}

static struct Sep3Endpoint *sep3__find_endpoint(struct Sep3 *self, DataId data_id)
{
    for (uint16_t i = 0; i < self->endpoint_capacity; ++i) {
        if (self->endpoints[i].is_used && (self->endpoints[i].data_id == data_id)) {
            return &self->endpoints[i];
        }
    }
    return NULL;
}

static struct Sep3Endpoint *sep3__get_or_create_endpoint(struct Sep3 *self, DataId data_id)
{
    struct Sep3Endpoint *endpoint = sep3__find_endpoint(self, data_id);

    if (NULL != endpoint) {
        return endpoint;
    }
    for (uint16_t i = 0; i < self->endpoint_capacity; ++i) {
        if (!self->endpoints[i].is_used) {
            endpoint = &self->endpoints[i];
            memset(endpoint, 0, sizeof(*endpoint));
            endpoint->is_used = true;
            endpoint->data_id = data_id;
            ++self->endpoint_count;
            return endpoint;
        }
    }
    return NULL;
}

static void sep3__finish_outgoing_error(struct Sep3 *self, int result)
{
    Sep3RequestCallback callback = self->outgoing.callback;
    void *callback_user = self->outgoing.callback_user;
    struct Sep3RequestResult request_result = {
        .result = result,
    };

    self->outgoing.active = false;
    self->outgoing.timeout_started = false;
    self->outgoing.callback = NULL;
    self->outgoing.callback_user = NULL;
    if (NULL != callback) {
        callback(self, &request_result, callback_user);
    }
}

static void sep3__pop_tx_slot(struct Sep3 *self)
{
    struct Sep3TxSlot *slot = &self->buffers->tx[self->tx_head];

    memset(slot, 0, sizeof(*slot));
    self->tx_head = (uint8_t)((self->tx_head + 1U) % SEP3_TX_SLOT_COUNT);
    --self->tx_count;
}

static int sep3__try_submit_tx(struct Sep3 *self, bool notify_failure)
{
    struct Sep3TxSlot *slot = NULL;
    int rc = 0;
    uint8_t purpose = 0;
    uint32_t generation = 0;

    if (0 == self->tx_count) {
        return 0;
    }

    slot = &self->buffers->tx[self->tx_head];
    if (SEP3_TX_QUEUED != slot->state) {
        return 0;
    }

    slot->state = SEP3_TX_IN_FLIGHT;
    rc = self->transmit(
        self,
        slot->data,
        slot->frame_size,
        self->tx_head,
        self->transmit_user);
    if (0 == rc) {
        return 0;
    }
    if (ER_AGAIN == rc) {
        slot->state = SEP3_TX_QUEUED;
        return 0;
    }

    purpose = slot->purpose;
    generation = slot->generation;
    sep3__pop_tx_slot(self);
    if (notify_failure &&
        (SEP3_TX_PURPOSE_OUTGOING_REQUEST == purpose) &&
        self->outgoing.active &&
        (self->outgoing.generation == generation)) {
        sep3__finish_outgoing_error(self, ER_IO);
    }
    return rc;
}

static int sep3__queue_packet(
    struct Sep3 *self,
    uint8_t const *packet,
    uint16_t packet_size,
    uint8_t purpose,
    uint32_t generation,
    bool notify_failure)
{
    uint8_t slot_id = 0;
    struct Sep3TxSlot *slot = NULL;
    int frame_size = 0;
    int rc = 0;

    if (self->tx_count >= SEP3_TX_SLOT_COUNT) {
        return ER_AGAIN;
    }

    slot_id = (uint8_t)((self->tx_head + self->tx_count) % SEP3_TX_SLOT_COUNT);
    slot = &self->buffers->tx[slot_id];
    memcpy(slot->data, packet, packet_size);
    frame_size = framer7b__encode_in_place(
        slot->data,
        packet_size,
        (uint16_t)sizeof(slot->data));
    if (frame_size < 0) {
        memset(slot, 0, sizeof(*slot));
        return frame_size;
    }

    slot->frame_size = (uint16_t)frame_size;
    slot->generation = generation;
    slot->purpose = purpose;
    slot->state = SEP3_TX_QUEUED;
    ++self->tx_count;

    rc = sep3__try_submit_tx(self, notify_failure);
    return rc;
}

static int sep3__queue_incoming_answer(struct Sep3 *self)
{
    int rc = 0;

    if (!self->incoming.answer_pending || !self->incoming.has_answer) {
        return 0;
    }
    rc = sep3__queue_packet(
        self,
        self->buffers->incoming_answer,
        self->incoming.answer_size,
        SEP3_TX_PURPOSE_INCOMING_ANSWER,
        self->incoming.generation,
        true);
    if (0 == rc) {
        self->incoming.answer_pending = false;
    } else if (ER_AGAIN != rc) {
        self->incoming.answer_pending = false;
    }
    return rc;
}

static bool sep3__token_is_valid(
    struct Sep3 const *self,
    struct Sep3RequestToken const *token)
{
    return (NULL != token) &&
        (token->owner == self) &&
        (token->epoch == self->token_epoch) &&
        self->incoming.valid &&
        self->incoming.active &&
        (token->generation == self->incoming.generation) &&
        (token->transaction_id == self->incoming.transaction_id) &&
        (token->data_id == self->incoming.data_id) &&
        (token->request_type == self->incoming.request_type);
}

static int sep3__set_incoming_answer(
    struct Sep3 *self,
    struct Sep3RequestToken const *token,
    Sep3PacketType answer_type,
    uint8_t const *payload,
    uint16_t payload_size)
{
    int rc = 0;

    if (!sep3__token_is_valid(self, token)) {
        return ER_INVAL;
    }
    rc = sep3__build_packet(
        self->buffers->incoming_answer,
        answer_type,
        token->transaction_id,
        token->data_id,
        payload,
        payload_size,
        &self->incoming.answer_size);
    if (0 != rc) {
        return rc;
    }

    self->incoming.active = false;
    self->incoming.has_answer = true;
    self->incoming.answer_pending = true;
    rc = sep3__queue_incoming_answer(self);
    if (ER_AGAIN == rc) {
        return 0;
    }
    return rc;
}

static int sep3__send_protocol_error_for_incoming(
    struct Sep3 *self,
    Sep3ProtocolError error)
{
    struct Sep3RequestToken token = {
        .owner = self,
        .epoch = self->token_epoch,
        .generation = self->incoming.generation,
        .transaction_id = self->incoming.transaction_id,
        .data_id = self->incoming.data_id,
        .request_type = self->incoming.request_type,
    };
    uint8_t payload = (uint8_t)error;

    return sep3__set_incoming_answer(
        self,
        &token,
        SEP3_PACKET_PROTO_ERROR_ANSWER,
        &payload,
        1);
}

static int sep3__queue_transient_answer(struct Sep3 *self)
{
    int rc = 0;

    if (!self->transient_answer_pending) {
        return 0;
    }
    rc = sep3__queue_packet(
        self,
        self->buffers->transient_answer,
        self->transient_answer_size,
        SEP3_TX_PURPOSE_TRANSIENT_ANSWER,
        0,
        true);
    if (0 == rc) {
        self->transient_answer_pending = false;
    } else if (ER_AGAIN != rc) {
        self->transient_answer_pending = false;
    }
    return rc;
}

static void sep3__queue_transient_protocol_error(
    struct Sep3 *self,
    TransactionId transaction_id,
    DataId data_id,
    Sep3ProtocolError error)
{
    uint8_t payload = (uint8_t)error;

    if (self->transient_answer_pending) {
        return;
    }
    if (0 == sep3__build_packet(
            self->buffers->transient_answer,
            SEP3_PACKET_PROTO_ERROR_ANSWER,
            transaction_id,
            data_id,
            &payload,
            1,
            &self->transient_answer_size)) {
        self->transient_answer_pending = true;
        (void)sep3__queue_transient_answer(self);
    }
}

static void sep3__dispatch_incoming(struct Sep3 *self, uint8_t const *packet, uint16_t packet_size)
{
    Sep3PacketType type = (Sep3PacketType)packet[SEP3_TYPE_OFFSET];
    TransactionId transaction_id = sep3__read_u16_le(&packet[SEP3_TRANSACTION_ID_OFFSET]);
    DataId data_id = packet[SEP3_DATA_ID_OFFSET];
    uint16_t payload_size = (uint16_t)(packet_size - SEP3_MIN_PACKET_SIZE);
    uint8_t const *payload = &packet[SEP3_PAYLOAD_OFFSET];
    struct Sep3Endpoint *endpoint = NULL;

    if (SEP3_PACKET_WRITE_NO_ANSWER == type) {
        if (0 != transaction_id) {
            return;
        }
        endpoint = sep3__find_endpoint(self, data_id);
        if ((NULL != endpoint) &&
            (NULL != endpoint->on_write) &&
            endpoint->allow_write_no_answer) {
            endpoint->on_write(
                self,
                NULL,
                payload,
                payload_size,
                false,
                endpoint->on_write_user);
        }
        return;
    }

    if (0 == transaction_id) {
        if (self->incoming.active || self->incoming.answer_pending) {
            sep3__queue_transient_protocol_error(
                self,
                transaction_id,
                data_id,
                SEP3_PROTOCOL_ERROR_INVALID_TRANSACTION_ID);
            return;
        }
        self->incoming.valid = false;
        self->incoming.active = false;
        self->incoming.has_answer = false;
        self->incoming.answer_pending = false;
        ++self->token_generation;
        self->incoming.valid = true;
        self->incoming.active = true;
        self->incoming.request_type = type;
        self->incoming.transaction_id = transaction_id;
        self->incoming.data_id = data_id;
        self->incoming.generation = self->token_generation;
        (void)sep3__send_protocol_error_for_incoming(
            self,
            SEP3_PROTOCOL_ERROR_INVALID_TRANSACTION_ID);
        return;
    }

    if (self->incoming.valid && (self->incoming.transaction_id == transaction_id)) {
        bool same_request = (self->incoming.request_size == packet_size) &&
            (0 == memcmp(self->buffers->incoming_request, packet, packet_size));
        if (!same_request) {
            sep3__queue_transient_protocol_error(
                self,
                transaction_id,
                data_id,
                SEP3_PROTOCOL_ERROR_TRANSACTION_CONFLICT);
        } else if (self->incoming.has_answer) {
            self->incoming.answer_pending = true;
            (void)sep3__queue_incoming_answer(self);
        }
        return;
    }

    if (self->incoming.active) {
        sep3__queue_transient_protocol_error(
            self,
            transaction_id,
            data_id,
            SEP3_PROTOCOL_ERROR_BUSY);
        return;
    }

    if (self->incoming.answer_pending) {
        sep3__queue_transient_protocol_error(
            self,
            transaction_id,
            data_id,
            SEP3_PROTOCOL_ERROR_BUSY);
        return;
    }

    memcpy(self->buffers->incoming_request, packet, packet_size);
    ++self->token_generation;
    if (0 == self->token_generation) {
        ++self->token_generation;
    }
    self->incoming.valid = true;
    self->incoming.active = true;
    self->incoming.has_answer = false;
    self->incoming.answer_pending = false;
    self->incoming.request_type = type;
    self->incoming.transaction_id = transaction_id;
    self->incoming.data_id = data_id;
    self->incoming.request_size = packet_size;
    self->incoming.answer_size = 0;
    self->incoming.generation = self->token_generation;
    self->incoming.started_ms = self->now_ms;

    if ((SEP3_PACKET_READ == type) && (0 != payload_size)) {
        (void)sep3__send_protocol_error_for_incoming(
            self,
            SEP3_PROTOCOL_ERROR_INVALID_PAYLOAD_SIZE);
        return;
    }

    endpoint = sep3__find_endpoint(self, data_id);
    if ((SEP3_PACKET_READ == type) && (NULL != endpoint) && (NULL != endpoint->on_read)) {
        struct Sep3RequestToken token = {
            .owner = self,
            .epoch = self->token_epoch,
            .generation = self->incoming.generation,
            .transaction_id = transaction_id,
            .data_id = data_id,
            .request_type = type,
        };
        endpoint->on_read(self, &token, endpoint->on_read_user);
    } else if ((SEP3_PACKET_WRITE == type) &&
        (NULL != endpoint) &&
        (NULL != endpoint->on_write)) {
        struct Sep3RequestToken token = {
            .owner = self,
            .epoch = self->token_epoch,
            .generation = self->incoming.generation,
            .transaction_id = transaction_id,
            .data_id = data_id,
            .request_type = type,
        };
        endpoint->on_write(
            self,
            &token,
            &self->buffers->incoming_request[SEP3_PAYLOAD_OFFSET],
            payload_size,
            true,
            endpoint->on_write_user);
    } else {
        struct Sep3RequestToken token = {
            .owner = self,
            .epoch = self->token_epoch,
            .generation = self->incoming.generation,
            .transaction_id = transaction_id,
            .data_id = data_id,
            .request_type = type,
        };
        (void)sep3__send_error_answer(
            self,
            &token,
            SEP3_APPLICATION_ERROR_UNSPECIFIED,
            NULL);
    }
}

static bool sep3__app_error_payload_is_valid(uint8_t const *payload, uint16_t payload_size)
{
    if (0 == payload_size) {
        return false;
    }
    if (1 == payload_size) {
        return true;
    }
    if (0 != payload[payload_size - 1]) {
        return false;
    }
    return NULL == memchr(&payload[1], 0, payload_size - 2U);
}

static void sep3__dispatch_response(struct Sep3 *self, uint8_t const *packet, uint16_t packet_size)
{
    Sep3PacketType type = (Sep3PacketType)packet[SEP3_TYPE_OFFSET];
    TransactionId transaction_id = sep3__read_u16_le(&packet[SEP3_TRANSACTION_ID_OFFSET]);
    DataId data_id = packet[SEP3_DATA_ID_OFFSET];
    uint16_t payload_size = (uint16_t)(packet_size - SEP3_MIN_PACKET_SIZE);
    uint8_t const *payload = &packet[SEP3_PAYLOAD_OFFSET];
    bool expected_success = false;
    Sep3RequestCallback callback = NULL;
    void *callback_user = NULL;
    struct Sep3RequestResult result = {0};

    if (!self->outgoing.active ||
        (self->outgoing.transaction_id != transaction_id) ||
        (self->outgoing.data_id != data_id)) {
        return;
    }

    expected_success =
        ((SEP3_PACKET_READ == self->outgoing.request_type) &&
            (SEP3_PACKET_READ_ANSWER == type)) ||
        ((SEP3_PACKET_WRITE == self->outgoing.request_type) &&
            (SEP3_PACKET_WRITE_ANSWER == type));

    if (expected_success) {
        if ((SEP3_PACKET_WRITE_ANSWER == type) && (0 != payload_size)) {
            return;
        }
    } else if (SEP3_PACKET_PROTO_ERROR_ANSWER == type) {
        if (1 != payload_size) {
            return;
        }
    } else if (SEP3_PACKET_APP_ERROR_ANSWER == type) {
        if (!sep3__app_error_payload_is_valid(payload, payload_size)) {
            return;
        }
    } else {
        return;
    }

    result.result = 0;
    result.answer_type = type;
    if ((SEP3_PACKET_APP_ERROR_ANSWER == type) ||
        (SEP3_PACKET_PROTO_ERROR_ANSWER == type)) {
        result.remote_error_code = payload[0];
    }
    if (SEP3_PACKET_READ_ANSWER == type) {
        result.data = payload;
        result.data_size = payload_size;
    } else if ((SEP3_PACKET_APP_ERROR_ANSWER == type) && (payload_size > 1)) {
        result.remote_error_message = (char const *)&payload[1];
    }

    callback = self->outgoing.callback;
    callback_user = self->outgoing.callback_user;
    self->outgoing.active = false;
    self->outgoing.timeout_started = false;
    self->outgoing.callback = NULL;
    self->outgoing.callback_user = NULL;
    if (NULL != callback) {
        callback(self, &result, callback_user);
    }
}

static void sep3__process_packet(struct Sep3 *self, uint8_t const *packet, uint16_t packet_size)
{
    uint8_t type = 0;

    if ((packet_size < SEP3_MIN_PACKET_SIZE) ||
        (packet_size > SEP3_MAX_PACKET_SIZE) ||
        !sep3__packet_crc_is_valid(packet, packet_size)) {
        return;
    }

    type = packet[SEP3_TYPE_OFFSET];
    if (!sep3__is_packet_type(type)) {
        return;
    }

    if ((SEP3_PACKET_WRITE == type) ||
        (SEP3_PACKET_WRITE_NO_ANSWER == type) ||
        (SEP3_PACKET_READ == type)) {
        sep3__dispatch_incoming(self, packet, packet_size);
    } else {
        sep3__dispatch_response(self, packet, packet_size);
    }
}

static TransactionId sep3__allocate_transaction_id(struct Sep3 *self)
{
    TransactionId transaction_id = self->next_transaction_id;

    if (UINT16_MAX == self->next_transaction_id) {
        self->next_transaction_id = 1;
    } else {
        ++self->next_transaction_id;
    }
    return transaction_id;
}

static int sep3__start_request(
    struct Sep3 *self,
    Sep3PacketType type,
    DataId data_id,
    uint8_t const *data,
    uint16_t data_size,
    Sep3RequestCallback callback,
    void *user)
{
    TransactionId transaction_id = 0;
    int rc = 0;

    if ((NULL == self) || (NULL == callback)) {
        return ER_INVAL;
    }
    if (self->outgoing.active) {
        return ER_BUSY;
    }
    if (data_size > SEP3_MAX_PAYLOAD_SIZE) {
        return ER_OVERFLOW;
    }
    if ((0 != data_size) && (NULL == data)) {
        return ER_INVAL;
    }
    if (data_id >= SEP3_RESERVED_DATA_ID_START) {
        return ER_NOT_PERM;
    }

    transaction_id = sep3__allocate_transaction_id(self);
    ++self->token_generation;
    if (0 == self->token_generation) {
        ++self->token_generation;
    }
    memset(&self->outgoing, 0, sizeof(self->outgoing));
    self->outgoing.active = true;
    self->outgoing.request_type = type;
    self->outgoing.transaction_id = transaction_id;
    self->outgoing.data_id = data_id;
    self->outgoing.generation = self->token_generation;
    self->outgoing.callback = callback;
    self->outgoing.callback_user = user;

    rc = sep3__build_packet(
        self->buffers->outgoing_packet,
        type,
        transaction_id,
        data_id,
        data,
        data_size,
        &self->outgoing.packet_size);
    if (0 == rc) {
        rc = sep3__queue_packet(
            self,
            self->buffers->outgoing_packet,
            self->outgoing.packet_size,
            SEP3_TX_PURPOSE_OUTGOING_REQUEST,
            self->outgoing.generation,
            false);
    }
    if (0 != rc) {
        memset(&self->outgoing, 0, sizeof(self->outgoing));
        return rc;
    }

    return 0;
}

int sep3__init(struct Sep3 *self, struct Sep3Config const *config)
{
    int rc = 0;

    if ((NULL == self) ||
        (NULL == config) ||
        (NULL == config->buffers) ||
        (NULL == config->transmit) ||
        (0 == config->request_timeout_ms) ||
        (0 == config->incoming_request_timeout_ms) ||
        (0 == config->token_epoch) ||
        ((0 != config->endpoint_capacity) && (NULL == config->endpoints))) {
        return ER_INVAL;
    }

    memset(self, 0, sizeof(*self));
    memset(config->buffers, 0, sizeof(*config->buffers));
    if (0 != config->endpoint_capacity) {
        memset(config->endpoints, 0, sizeof(*config->endpoints) * config->endpoint_capacity);
    }

    self->buffers = config->buffers;
    self->endpoints = config->endpoints;
    self->endpoint_capacity = config->endpoint_capacity;
    self->request_timeout_ms = config->request_timeout_ms;
    self->incoming_request_timeout_ms = config->incoming_request_timeout_ms;
    self->token_epoch = config->token_epoch;
    self->retry_count = config->retry_count;
    self->transmit = config->transmit;
    self->transmit_user = config->transmit_user;
    self->next_transaction_id = 1;

    rc = framer7b_receiver__init(
        &self->framer,
        self->buffers->rx,
        (uint16_t)sizeof(self->buffers->rx));
    return rc;
}

int sep3__register_read_handler(
    struct Sep3 *self,
    DataId data_id,
    Sep3ReadHandler handler,
    void *user)
{
    struct Sep3Endpoint *endpoint = NULL;

    if ((NULL == self) || (NULL == handler)) {
        return ER_INVAL;
    }
    if (data_id >= SEP3_RESERVED_DATA_ID_START) {
        return ER_NOT_PERM;
    }
    endpoint = sep3__get_or_create_endpoint(self, data_id);
    if (NULL == endpoint) {
        return ER_NO_MEM;
    }
    if (NULL != endpoint->on_read) {
        return ER_ALREADY;
    }
    endpoint->on_read = handler;
    endpoint->on_read_user = user;
    return 0;
}

int sep3__register_write_handler(
    struct Sep3 *self,
    DataId data_id,
    bool allow_write_no_answer,
    Sep3WriteHandler handler,
    void *user)
{
    struct Sep3Endpoint *endpoint = NULL;

    if ((NULL == self) || (NULL == handler)) {
        return ER_INVAL;
    }
    if (data_id >= SEP3_RESERVED_DATA_ID_START) {
        return ER_NOT_PERM;
    }
    endpoint = sep3__get_or_create_endpoint(self, data_id);
    if (NULL == endpoint) {
        return ER_NO_MEM;
    }
    if (NULL != endpoint->on_write) {
        return ER_ALREADY;
    }
    endpoint->on_write = handler;
    endpoint->on_write_user = user;
    endpoint->allow_write_no_answer = allow_write_no_answer;
    return 0;
}

int sep3__handle_received(
    struct Sep3 *self,
    uint8_t const *data,
    uint16_t data_size)
{
    if ((NULL == self) || ((0 != data_size) && (NULL == data))) {
        return ER_INVAL;
    }
    if (self->handling_received) {
        return ER_BUSY;
    }

    self->handling_received = true;

    for (uint16_t i = 0; i < data_size; ++i) {
        uint8_t byte = data[i];
        uint16_t encoded_size = self->rx_encoded_size;
        uint8_t last_encoded_byte = self->rx_last_encoded_byte;
        bool was_started = self->rx_frame_started;
        int decoded_size = 0;

        if (SEP3_FRAMER_START == byte) {
            self->rx_frame_started = true;
            self->rx_encoded_size = 0;
            self->rx_last_encoded_byte = 0;
        } else if (0 != (byte & SEP3_FRAMER_MARK_MASK)) {
            if (SEP3_FRAMER_END == byte) {
                self->rx_frame_started = false;
            } else {
                self->rx_frame_started = false;
                self->rx_encoded_size = 0;
            }
        } else if (self->rx_frame_started) {
            if (self->rx_encoded_size < UINT16_MAX) {
                ++self->rx_encoded_size;
            }
            self->rx_last_encoded_byte = byte;
        }

        decoded_size = framer7b_receiver__push(&self->framer, byte);
        if (decoded_size > 0) {
            if (was_started &&
                sep3__framing_is_canonical(
                    encoded_size,
                    last_encoded_byte,
                    (uint16_t)decoded_size)) {
                sep3__process_packet(
                    self,
                    framer7b_receiver__buf(&self->framer),
                    (uint16_t)decoded_size);
            }
            self->rx_encoded_size = 0;
        } else if (decoded_size < 0) {
            self->rx_frame_started = false;
            self->rx_encoded_size = 0;
        }
    }
    self->handling_received = false;
    return 0;
}

int sep3__handle_transmitted(struct Sep3 *self, uint8_t slot_id, int result)
{
    struct Sep3TxSlot *slot = NULL;
    uint8_t purpose = 0;
    uint32_t generation = 0;

    if ((NULL == self) || (slot_id >= SEP3_TX_SLOT_COUNT)) {
        return ER_INVAL;
    }
    if ((0 == self->tx_count) || (slot_id != self->tx_head)) {
        return ER_INVAL;
    }

    slot = &self->buffers->tx[slot_id];
    if (SEP3_TX_IN_FLIGHT != slot->state) {
        return ER_INVAL;
    }
    purpose = slot->purpose;
    generation = slot->generation;
    sep3__pop_tx_slot(self);

    if ((SEP3_TX_PURPOSE_OUTGOING_REQUEST == purpose) &&
        self->outgoing.active &&
        (self->outgoing.generation == generation)) {
        if (0 == result) {
            self->outgoing.timeout_started = true;
            self->outgoing.timeout_started_ms = self->now_ms;
        } else {
            sep3__finish_outgoing_error(self, ER_IO);
        }
    }

    (void)sep3__try_submit_tx(self, true);
    (void)sep3__queue_incoming_answer(self);
    (void)sep3__queue_transient_answer(self);
    return 0;
}

int sep3__process(struct Sep3 *self, uint64_t now_ms)
{
    int rc = 0;

    if (NULL == self) {
        return ER_INVAL;
    }
    if (self->time_initialized && (now_ms < self->now_ms)) {
        return ER_INVAL;
    }
    if (!self->time_initialized) {
        if (self->incoming.active) {
            self->incoming.started_ms = now_ms;
        }
        if (self->outgoing.timeout_started) {
            self->outgoing.timeout_started_ms = now_ms;
        }
        self->time_initialized = true;
    }
    self->now_ms = now_ms;

    rc = sep3__try_submit_tx(self, true);
    if ((0 != rc) && (ER_AGAIN != rc)) {
        return rc;
    }
    rc = sep3__queue_incoming_answer(self);
    if ((0 != rc) && (ER_AGAIN != rc)) {
        return rc;
    }
    rc = sep3__queue_transient_answer(self);
    if ((0 != rc) && (ER_AGAIN != rc)) {
        return rc;
    }

    if (self->incoming.active &&
        ((now_ms - self->incoming.started_ms) >= self->incoming_request_timeout_ms)) {
        self->incoming.active = false;
        self->incoming.has_answer = false;
        self->incoming.answer_pending = false;
    }

    if (self->outgoing.active &&
        self->outgoing.timeout_started &&
        ((now_ms - self->outgoing.timeout_started_ms) >= self->request_timeout_ms)) {
        if (self->outgoing.retries_done >= self->retry_count) {
            sep3__finish_outgoing_error(self, ER_TIMEDOUT);
        } else {
            rc = sep3__queue_packet(
                self,
                self->buffers->outgoing_packet,
                self->outgoing.packet_size,
                SEP3_TX_PURPOSE_OUTGOING_REQUEST,
                self->outgoing.generation,
                false);
            if (0 == rc) {
                ++self->outgoing.retries_done;
                self->outgoing.timeout_started = false;
            } else if (ER_AGAIN != rc) {
                sep3__finish_outgoing_error(self, ER_IO);
                return rc;
            }
        }
    }
    return 0;
}

int sep3__read(
    struct Sep3 *self,
    DataId data_id,
    Sep3RequestCallback callback,
    void *user)
{
    return sep3__start_request(
        self,
        SEP3_PACKET_READ,
        data_id,
        NULL,
        0,
        callback,
        user);
}

int sep3__write(
    struct Sep3 *self,
    DataId data_id,
    uint8_t const *data,
    uint16_t data_size,
    Sep3RequestCallback callback,
    void *user)
{
    return sep3__start_request(
        self,
        SEP3_PACKET_WRITE,
        data_id,
        data,
        data_size,
        callback,
        user);
}

int sep3__write_no_answer(
    struct Sep3 *self,
    DataId data_id,
    uint8_t const *data,
    uint16_t data_size)
{
    uint8_t packet[SEP3_MAX_PACKET_SIZE] = {0};
    uint16_t packet_size = 0;
    int rc = 0;

    if (NULL == self) {
        return ER_INVAL;
    }
    if (data_id >= SEP3_RESERVED_DATA_ID_START) {
        return ER_NOT_PERM;
    }
    rc = sep3__build_packet(
        packet,
        SEP3_PACKET_WRITE_NO_ANSWER,
        0,
        data_id,
        data,
        data_size,
        &packet_size);
    if (0 != rc) {
        return rc;
    }
    return sep3__queue_packet(
        self,
        packet,
        packet_size,
        SEP3_TX_PURPOSE_UNACKNOWLEDGED,
        0,
        false);
}

int sep3__send_read_answer(
    struct Sep3 *self,
    struct Sep3RequestToken const *token,
    uint8_t const *data,
    uint16_t data_size)
{
    if ((NULL == self) || (NULL == token)) {
        return ER_INVAL;
    }
    if (SEP3_PACKET_READ != token->request_type) {
        return ER_INVAL;
    }
    return sep3__set_incoming_answer(
        self,
        token,
        SEP3_PACKET_READ_ANSWER,
        data,
        data_size);
}

int sep3__send_write_answer(
    struct Sep3 *self,
    struct Sep3RequestToken const *token)
{
    if ((NULL == self) || (NULL == token)) {
        return ER_INVAL;
    }
    if (SEP3_PACKET_WRITE != token->request_type) {
        return ER_INVAL;
    }
    return sep3__set_incoming_answer(
        self,
        token,
        SEP3_PACKET_WRITE_ANSWER,
        NULL,
        0);
}

int sep3__send_error_answer(
    struct Sep3 *self,
    struct Sep3RequestToken const *token,
    uint8_t error_code,
    char const *message)
{
    uint8_t payload[SEP3_MAX_PAYLOAD_SIZE] = {0};
    uint16_t message_size = 0;

    if ((NULL == self) || (NULL == token)) {
        return ER_INVAL;
    }
    if (NULL != message) {
        while ((message_size < (SEP3_MAX_PAYLOAD_SIZE - 1U)) &&
            ('\0' != message[message_size])) {
            ++message_size;
        }
        if ((message_size >= (SEP3_MAX_PAYLOAD_SIZE - 1U)) ||
            ('\0' != message[message_size])) {
            return ER_OVERFLOW;
        }
        ++message_size;
    }

    payload[0] = error_code;
    if (0 != message_size) {
        memcpy(&payload[1], message, message_size);
    }
    return sep3__set_incoming_answer(
        self,
        token,
        SEP3_PACKET_APP_ERROR_ANSWER,
        payload,
        (uint16_t)(1U + message_size));
}
