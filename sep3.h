/** @file sep3.h Serial Embedded Peer to Peer Protocol. */

#ifndef SEP3_H_
#define SEP3_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <framer7b.h>
#include <safe_c.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SEP3_MAX_PAYLOAD_SIZE = 244,
    SEP3_MAX_PACKET_SIZE = 250,
    SEP3_MAX_ENCODED_BODY_SIZE = 286,
    SEP3_MAX_ENCODED_FRAME_SIZE = 288,
    SEP3_TX_SLOT_COUNT = 2,
};

typedef uint8_t DataId;
typedef uint16_t TransactionId;

typedef enum Sep3PacketType {
    SEP3_PACKET_WRITE = 0x01,
    SEP3_PACKET_WRITE_NO_ANSWER = 0x02,
    SEP3_PACKET_READ = 0x08,
    SEP3_PACKET_WRITE_ANSWER = 0x81,
    SEP3_PACKET_READ_ANSWER = 0x88,
    SEP3_PACKET_APP_ERROR_ANSWER = 0xFE,
    SEP3_PACKET_PROTO_ERROR_ANSWER = 0xFF,
} Sep3PacketType;

typedef enum Sep3ProtocolError {
    SEP3_PROTOCOL_ERROR_INVALID_PAYLOAD_SIZE = 0x01,
    SEP3_PROTOCOL_ERROR_INVALID_TRANSACTION_ID = 0x02,
    SEP3_PROTOCOL_ERROR_BUSY = 0x03,
    SEP3_PROTOCOL_ERROR_TRANSACTION_CONFLICT = 0x04,
} Sep3ProtocolError;

typedef enum Sep3ApplicationError {
    SEP3_APPLICATION_ERROR_UNSPECIFIED = 0x00,
} Sep3ApplicationError;

typedef struct Sep3 Sep3;

typedef struct Sep3RequestToken {
    struct Sep3 *owner;
    uint32_t epoch;
    uint32_t generation;
    TransactionId transaction_id;
    DataId data_id;
    Sep3PacketType request_type;
} Sep3RequestToken;

typedef struct Sep3RequestResult {
    int result;
    Sep3PacketType answer_type;
    uint8_t remote_error_code;
    uint8_t const *data;
    uint16_t data_size;
    char const *remote_error_message;
} Sep3RequestResult;

typedef void (*Sep3ReadHandler)(
    struct Sep3 *self,
    struct Sep3RequestToken const *token,
    void *user);

typedef void (*Sep3WriteHandler)(
    struct Sep3 *self,
    struct Sep3RequestToken const *token,
    uint8_t const *data,
    uint16_t data_size,
    bool is_need_answer,
    void *user);

typedef void (*Sep3RequestCallback)(
    struct Sep3 *self,
    struct Sep3RequestResult const *result,
    void *user);

/** Submit an encoded frame to the platform transport.
 *
 * The frame remains valid until sep3__handle_transmitted() is called for
 * slot_id. Return 0 when the frame was accepted, ER_AGAIN when the transport is
 * temporarily busy, or another ErrorCodes value on failure. The callback must
 * not call sep3__handle_transmitted() before returning. For every accepted
 * frame, the transport must call sep3__handle_transmitted() exactly once and
 * only after it no longer accesses the frame buffer.
 */
typedef int (*Sep3TransmitHandler)(
    struct Sep3 *self,
    uint8_t const *frame,
    uint16_t frame_size,
    uint8_t slot_id,
    void *user);

typedef struct Sep3Endpoint {
    DataId data_id;
    bool is_used;
    bool allow_write_no_answer;
    Sep3ReadHandler on_read;
    void *on_read_user;
    Sep3WriteHandler on_write;
    void *on_write_user;
} Sep3Endpoint;

typedef struct Sep3TxSlot {
    uint8_t data[SEP3_MAX_ENCODED_FRAME_SIZE];
    uint16_t frame_size;
    uint32_t generation;
    uint8_t state;
    uint8_t purpose;
} Sep3TxSlot;

typedef struct Sep3Buffers {
    uint8_t rx[SEP3_MAX_ENCODED_BODY_SIZE];
    uint8_t outgoing_packet[SEP3_MAX_PACKET_SIZE];
    uint8_t incoming_request[SEP3_MAX_PACKET_SIZE];
    uint8_t incoming_answer[SEP3_MAX_PACKET_SIZE];
    uint8_t transient_answer[SEP3_MAX_PACKET_SIZE];
    struct Sep3TxSlot tx[SEP3_TX_SLOT_COUNT];
} Sep3Buffers;

typedef struct Sep3Config {
    struct Sep3Buffers *buffers;
    struct Sep3Endpoint *endpoints;
    uint16_t endpoint_capacity;
    uint32_t request_timeout_ms;
    uint32_t incoming_request_timeout_ms;
    uint32_t token_epoch;
    uint8_t retry_count;
    Sep3TransmitHandler transmit;
    void *transmit_user;
} Sep3Config;

typedef struct Sep3OutgoingTransaction {
    bool active;
    bool timeout_started;
    Sep3PacketType request_type;
    TransactionId transaction_id;
    DataId data_id;
    uint16_t packet_size;
    uint32_t generation;
    uint8_t retries_done;
    uint64_t timeout_started_ms;
    Sep3RequestCallback callback;
    void *callback_user;
} Sep3OutgoingTransaction;

typedef struct Sep3IncomingTransaction {
    bool valid;
    bool active;
    bool has_answer;
    bool answer_pending;
    Sep3PacketType request_type;
    TransactionId transaction_id;
    DataId data_id;
    uint16_t request_size;
    uint16_t answer_size;
    uint32_t generation;
    uint64_t started_ms;
} Sep3IncomingTransaction;

typedef struct Sep3 {
    struct Framer7bReceiver framer;
    struct Sep3Buffers *buffers;
    struct Sep3Endpoint *endpoints;
    uint16_t endpoint_capacity;
    uint16_t endpoint_count;
    uint32_t request_timeout_ms;
    uint32_t incoming_request_timeout_ms;
    uint8_t retry_count;
    Sep3TransmitHandler transmit;
    void *transmit_user;
    TransactionId next_transaction_id;
    struct Sep3OutgoingTransaction outgoing;
    struct Sep3IncomingTransaction incoming;
    uint64_t now_ms;
    uint32_t token_epoch;
    uint32_t token_generation;
    uint16_t transient_answer_size;
    uint16_t rx_encoded_size;
    uint8_t rx_last_encoded_byte;
    uint8_t tx_head;
    uint8_t tx_count;
    bool rx_frame_started;
    bool handling_received;
    bool transient_answer_pending;
    bool time_initialized;
} Sep3;

/** Initialize or reset an SEP3 instance and all caller-provided storage.
 *
 * config->token_epoch must be nonzero and unique for every initialization of
 * the same object. Initialization is forbidden while the transport owns a TX
 * slot from the previous initialization.
 */
int sep3__init(struct Sep3 *self, struct Sep3Config const *config);

/** Register a READ handler for data_id. Registration lasts until sep3__init(). */
int sep3__register_read_handler(
    struct Sep3 *self,
    DataId data_id,
    Sep3ReadHandler handler,
    void *user);

/** Register a WRITE handler for data_id. */
int sep3__register_write_handler(
    struct Sep3 *self,
    DataId data_id,
    bool allow_write_no_answer,
    Sep3WriteHandler handler,
    void *user);

/** Process bytes received from the platform transport.
 *
 * Application handlers may be called before this function returns. Recoverable
 * framing and packet errors are discarded and do not stop processing the rest
 * of data.
 */
int sep3__handle_received(
    struct Sep3 *self,
    uint8_t const *data,
    uint16_t data_size);

/** Notify SEP3 that asynchronous transmission of slot_id has completed. */
int sep3__handle_transmitted(
    struct Sep3 *self,
    uint8_t slot_id,
    int result);

/** Process timers and retry queued transport submissions. */
int sep3__process(struct Sep3 *self, uint64_t now_ms);

/** Start an asynchronous READ transaction. */
int sep3__read(
    struct Sep3 *self,
    DataId data_id,
    Sep3RequestCallback callback,
    void *user);

/** Start an asynchronous WRITE transaction. */
int sep3__write(
    struct Sep3 *self,
    DataId data_id,
    uint8_t const *data,
    uint16_t data_size,
    Sep3RequestCallback callback,
    void *user);

/** Queue a best-effort WRITE_NO_ANSWER packet. */
int sep3__write_no_answer(
    struct Sep3 *self,
    DataId data_id,
    uint8_t const *data,
    uint16_t data_size);

/** Send a successful READ response. */
int sep3__send_read_answer(
    struct Sep3 *self,
    struct Sep3RequestToken const *token,
    uint8_t const *data,
    uint16_t data_size);

/** Send a successful WRITE response. */
int sep3__send_write_answer(
    struct Sep3 *self,
    struct Sep3RequestToken const *token);

/** Send an application error response.
 *
 * message is either NULL or a NULL-terminated UTF-8 string. The terminator is
 * transmitted and included in the payload size.
 */
int sep3__send_error_answer(
    struct Sep3 *self,
    struct Sep3RequestToken const *token,
    uint8_t error_code,
    char const *message);

#ifdef __cplusplus
}
#endif

#endif
