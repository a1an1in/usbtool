#ifndef LIBUSB_H
#define LIBUSB_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <limits.h>
#include <sys/time.h>

#define LIBUSB_CALL


#ifdef __cplusplus
extern "C" {
#endif

/** \def libusb_cpu_to_le16
 * \ingroup misc
 * Convert a 16-bit value from host-endian to little-endian format. On
 * little endian systems, this function does nothing. On big endian systems,
 * the bytes are swapped.
 * \param x the host-endian value to convert
 * \returns the value in little-endian byte order
 */
static inline uint16_t libusb_cpu_to_le16(const uint16_t x)
{
	union {
		uint8_t  b8[2];
		uint16_t b16;
	} _tmp;
	_tmp.b8[1] = x >> 8;
	_tmp.b8[0] = x & 0xff;
	return _tmp.b16;
}

/** \def libusb_le16_to_cpu
 * \ingroup misc
 * Convert a 16-bit value from little-endian to host-endian format. On
 * little endian systems, this function does nothing. On big endian systems,
 * the bytes are swapped.
 * \param x the little-endian value to convert
 * \returns the value in host-endian byte order
 */
#define libusb_le16_to_cpu libusb_cpu_to_le16

/* standard USB stuff */

/** \ingroup desc
 * Device and/or Interface Class codes */
enum libusb_class_code {
	/** In the context of a \ref libusb_device_descriptor "device descriptor",
	 * this bDeviceClass value indicates that each interface specifies its
	 * own class information and all interfaces operate independently.
	 */
	LIBUSB_CLASS_PER_INTERFACE = 0,

	/** Audio class */
	LIBUSB_CLASS_AUDIO = 1,

	/** Communications class */
	LIBUSB_CLASS_COMM = 2,

	/** Human Interface Device class */
	LIBUSB_CLASS_HID = 3,

	/** Physical */
	LIBUSB_CLASS_PHYSICAL = 5,

	/** Printer class */
	LIBUSB_CLASS_PRINTER = 7,

	/** Image class */
	LIBUSB_CLASS_PTP = 6, /* legacy name from libusb-0.1 usb.h */
	LIBUSB_CLASS_IMAGE = 6,

	/** Mass storage class */
	LIBUSB_CLASS_MASS_STORAGE = 8,

	/** Hub class */
	LIBUSB_CLASS_HUB = 9,

	/** Data class */
	LIBUSB_CLASS_DATA = 10,

	/** Smart Card */
	LIBUSB_CLASS_SMART_CARD = 0x0b,

	/** Content Security */
	LIBUSB_CLASS_CONTENT_SECURITY = 0x0d,

	/** Video */
	LIBUSB_CLASS_VIDEO = 0x0e,

	/** Personal Healthcare */
	LIBUSB_CLASS_PERSONAL_HEALTHCARE = 0x0f,

	/** Diagnostic Device */
	LIBUSB_CLASS_DIAGNOSTIC_DEVICE = 0xdc,

	/** Wireless class */
	LIBUSB_CLASS_WIRELESS = 0xe0,

	/** Application class */
	LIBUSB_CLASS_APPLICATION = 0xfe,

	/** Class is vendor-specific */
	LIBUSB_CLASS_VENDOR_SPEC = 0xff
};

/** \ingroup desc
 * Descriptor types as defined by the USB specification. */
enum libusb_descriptor_type {
	/** Device descriptor. See libusb_device_descriptor. */
	LIBUSB_DT_DEVICE = 0x01,

	/** Configuration descriptor. See libusb_config_descriptor. */
	LIBUSB_DT_CONFIG = 0x02,

	/** String descriptor */
	LIBUSB_DT_STRING = 0x03,

	/** Interface descriptor. See libusb_interface_descriptor. */
	LIBUSB_DT_INTERFACE = 0x04,

	/** Endpoint descriptor. See libusb_endpoint_descriptor. */
	LIBUSB_DT_ENDPOINT = 0x05,

	/** HID descriptor */
	LIBUSB_DT_HID = 0x21,

	/** HID report descriptor */
	LIBUSB_DT_REPORT = 0x22,

	/** Physical descriptor */
	LIBUSB_DT_PHYSICAL = 0x23,

	/** Hub descriptor */
	LIBUSB_DT_HUB = 0x29,
};

/* Descriptor sizes per descriptor type */
#define LIBUSB_DT_DEVICE_SIZE			18
#define LIBUSB_DT_CONFIG_SIZE			9
#define LIBUSB_DT_INTERFACE_SIZE		9
#define LIBUSB_DT_ENDPOINT_SIZE		7
#define LIBUSB_DT_ENDPOINT_AUDIO_SIZE	9	/* Audio extension */
#define LIBUSB_DT_HUB_NONVAR_SIZE		7

#define LIBUSB_ENDPOINT_ADDRESS_MASK	0x0f    /* in bEndpointAddress */
#define LIBUSB_ENDPOINT_DIR_MASK		0x80

/** \ingroup desc
 * Endpoint direction. Values for bit 7 of the
 * \ref libusb_endpoint_descriptor::bEndpointAddress "endpoint address" scheme.
 */
enum libusb_endpoint_direction {
	/** In: device-to-host */
	LIBUSB_ENDPOINT_IN = 0x80,

	/** Out: host-to-device */
	LIBUSB_ENDPOINT_OUT = 0x00
};

#define LIBUSB_TRANSFER_TYPE_MASK			0x03    /* in bmAttributes */

/** \ingroup desc
 * Endpoint transfer type. Values for bits 0:1 of the
 * \ref libusb_endpoint_descriptor::bmAttributes "endpoint attributes" field.
 */
enum libusb_transfer_type {
	/** Control endpoint */
	LIBUSB_TRANSFER_TYPE_CONTROL = 0,

	/** Isochronous endpoint */
	LIBUSB_TRANSFER_TYPE_ISOCHRONOUS = 1,

	/** Bulk endpoint */
	LIBUSB_TRANSFER_TYPE_BULK = 2,

	/** Interrupt endpoint */
	LIBUSB_TRANSFER_TYPE_INTERRUPT = 3
};

/** \ingroup misc
 * Standard requests, as defined in table 9-3 of the USB2 specifications */
enum libusb_standard_request {
	/** Request status of the specific recipient */
	LIBUSB_REQUEST_GET_STATUS = 0x00,

	/** Clear or disable a specific feature */
	LIBUSB_REQUEST_CLEAR_FEATURE = 0x01,

	/* 0x02 is reserved */

	/** Set or enable a specific feature */
	LIBUSB_REQUEST_SET_FEATURE = 0x03,

	/* 0x04 is reserved */

	/** Set device address for all future accesses */
	LIBUSB_REQUEST_SET_ADDRESS = 0x05,

	/** Get the specified descriptor */
	LIBUSB_REQUEST_GET_DESCRIPTOR = 0x06,

	/** Used to update existing descriptors or add new descriptors */
	LIBUSB_REQUEST_SET_DESCRIPTOR = 0x07,

	/** Get the current device configuration value */
	LIBUSB_REQUEST_GET_CONFIGURATION = 0x08,

	/** Set device configuration */
	LIBUSB_REQUEST_SET_CONFIGURATION = 0x09,

	/** Return the selected alternate setting for the specified interface */
	LIBUSB_REQUEST_GET_INTERFACE = 0x0A,

	/** Select an alternate interface for the specified interface */
	LIBUSB_REQUEST_SET_INTERFACE = 0x0B,

	/** Set then report an endpoint's synchronization frame */
	LIBUSB_REQUEST_SYNCH_FRAME = 0x0C,
};

/** \ingroup misc
 * Request type bits of the
 * \ref libusb_control_setup::bmRequestType "bmRequestType" field in control
 * transfers. */
enum libusb_request_type {
	/** Standard */
	LIBUSB_REQUEST_TYPE_STANDARD = (0x00 << 5),

	/** Class */
	LIBUSB_REQUEST_TYPE_CLASS = (0x01 << 5),

	/** Vendor */
	LIBUSB_REQUEST_TYPE_VENDOR = (0x02 << 5),

	/** Reserved */
	LIBUSB_REQUEST_TYPE_RESERVED = (0x03 << 5)
};

/** \ingroup misc
 * Recipient bits of the
 * \ref libusb_control_setup::bmRequestType "bmRequestType" field in control
 * transfers. Values 4 through 31 are reserved. */
enum libusb_request_recipient {
	/** Device */
	LIBUSB_RECIPIENT_DEVICE = 0x00,

	/** Interface */
	LIBUSB_RECIPIENT_INTERFACE = 0x01,

	/** Endpoint */
	LIBUSB_RECIPIENT_ENDPOINT = 0x02,

	/** Other */
	LIBUSB_RECIPIENT_OTHER = 0x03,
};

#define LIBUSB_ISO_SYNC_TYPE_MASK		0x0C

/** \ingroup desc
 * Synchronization type for isochronous endpoints. Values for bits 2:3 of the
 * \ref libusb_endpoint_descriptor::bmAttributes "bmAttributes" field in
 * libusb_endpoint_descriptor.
 */
enum libusb_iso_sync_type {
	/** No synchronization */
	LIBUSB_ISO_SYNC_TYPE_NONE = 0,

	/** Asynchronous */
	LIBUSB_ISO_SYNC_TYPE_ASYNC = 1,

	/** Adaptive */
	LIBUSB_ISO_SYNC_TYPE_ADAPTIVE = 2,

	/** Synchronous */
	LIBUSB_ISO_SYNC_TYPE_SYNC = 3
};

#define LIBUSB_ISO_USAGE_TYPE_MASK 0x30

enum libusb_iso_usage_type {
	LIBUSB_ISO_USAGE_TYPE_DATA = 0,
	LIBUSB_ISO_USAGE_TYPE_FEEDBACK = 1,
	LIBUSB_ISO_USAGE_TYPE_IMPLICIT = 2,
};

struct libusb_device_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdUSB;
	uint8_t  bDeviceClass;
	uint8_t  bDeviceSubClass;
	uint8_t  bDeviceProtocol;
	uint8_t  bMaxPacketSize0;
	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;
	uint8_t  iManufacturer;
	uint8_t  iProduct;
	uint8_t  iSerialNumber;
	uint8_t  bNumConfigurations;
};

struct libusb_endpoint_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bEndpointAddress;
	uint8_t  bmAttributes;
	uint16_t wMaxPacketSize;
	uint8_t  bInterval;
	uint8_t  bRefresh;
	uint8_t  bSynchAddress;
	const unsigned char *extra;
	int extra_length;
};

struct libusb_interface_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bInterfaceNumber;
	uint8_t  bAlternateSetting;
	uint8_t  bNumEndpoints;
	uint8_t  bInterfaceClass;
	uint8_t  bInterfaceSubClass;
	uint8_t  bInterfaceProtocol;
	uint8_t  iInterface;
	const struct libusb_endpoint_descriptor *endpoint;
	const unsigned char *extra;
	int extra_length;
};

struct libusb_interface {
	const struct libusb_interface_descriptor *altsetting;
	int num_altsetting;
};

struct libusb_config_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t wTotalLength;
	uint8_t  bNumInterfaces;
	uint8_t  bConfigurationValue;
	uint8_t  iConfiguration;
	uint8_t  bmAttributes;
	uint8_t  MaxPower;
	const struct libusb_interface *interface;
	const unsigned char *extra;
	int extra_length;
};

/**
 *Setup packet for control transfers.*/
struct libusb_control_setup {
	uint8_t  bmRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
};

#define LIBUSB_CONTROL_SETUP_SIZE (sizeof(struct libusb_control_setup))

/* libusb */

struct libusb_context;
struct libusb_device;
struct libusb_device_handle;

/** \ingroup lib
 * Structure representing the libusb version.
 */
struct libusb_version {
	/** Library major version. */
	const uint16_t major;

	/** Library minor version. */
	const uint16_t minor;

	/** Library micro version. */
	const uint16_t micro;

	/** Library nano version. This field is only nonzero on Windows. */
	const uint16_t nano;

	/** Library release candidate suffix string, e.g. "-rc4". */
	const char *rc;

	/** Output of `git describe --tags` at library build time. */
	const char *describe;
};

typedef struct libusb_context libusb_context;
typedef struct libusb_device libusb_device;
typedef struct libusb_device_handle libusb_device_handle;

/** \ingroup dev
 * Speed codes. Indicates the speed at which the device is operating.
 */
enum libusb_speed {
    /** The OS doesn't report or know the device speed. */
    LIBUSB_SPEED_UNKNOWN = 0,

    /** The device is operating at low speed (1.5MBit/s). */
    LIBUSB_SPEED_LOW = 1,

    /** The device is operating at full speed (12MBit/s). */
    LIBUSB_SPEED_FULL = 2,

    /** The device is operating at high speed (480MBit/s). */
    LIBUSB_SPEED_HIGH = 3,

    /** The device is operating at super speed (5000MBit/s). */
    LIBUSB_SPEED_SUPER = 4,
};

/** \ingroup misc
 * Error codes. Most libusb functions return 0 on success or one of these
 * codes on failure.
 * You can call \ref libusb_error_name() to retrieve a string representation
 * of an error code.
 */
enum libusb_error {
	/** Success (no error) */
	LIBUSB_SUCCESS = 0,

	/** Input/output error */
	LIBUSB_ERROR_IO = -1,

	/** Invalid parameter */
	LIBUSB_ERROR_INVALID_PARAM = -2,

	/** Access denied (insufficient permissions) */
	LIBUSB_ERROR_ACCESS = -3,

	/** No such device (it may have been disconnected) */
	LIBUSB_ERROR_NO_DEVICE = -4,

	/** Entity not found */
	LIBUSB_ERROR_NOT_FOUND = -5,

	/** Resource busy */
	LIBUSB_ERROR_BUSY = -6,

	/** Operation timed out */
	LIBUSB_ERROR_TIMEOUT = -7,

	/** Overflow */
	LIBUSB_ERROR_OVERFLOW = -8,

	/** Pipe error */
	LIBUSB_ERROR_PIPE = -9,

	/** System call interrupted (perhaps due to signal) */
	LIBUSB_ERROR_INTERRUPTED = -10,

	/** Insufficient memory */
	LIBUSB_ERROR_NO_MEM = -11,

	/** Operation not supported or unimplemented on this platform */
	LIBUSB_ERROR_NOT_SUPPORTED = -12,

	/* NB! Remember to update libusb_error_name()
	   when adding new error codes here. */

	/** Other error */
	LIBUSB_ERROR_OTHER = -99,
};

/** \ingroup asyncio
 * Transfer status codes */
enum libusb_transfer_status {
	/** Transfer completed without error. Note that this does not indicate
	 * that the entire amount of requested data was transferred. */
	LIBUSB_TRANSFER_COMPLETED,

	/** Transfer failed */
	LIBUSB_TRANSFER_ERROR,

	/** Transfer timed out */
	LIBUSB_TRANSFER_TIMED_OUT,

	/** Transfer was cancelled */
	LIBUSB_TRANSFER_CANCELLED,

	/** For bulk/interrupt endpoints: halt condition detected (endpoint
	 * stalled). For control endpoints: control request not supported. */
	LIBUSB_TRANSFER_STALL,

	/** Device was disconnected */
	LIBUSB_TRANSFER_NO_DEVICE,

	/** Device sent more data than requested */
	LIBUSB_TRANSFER_OVERFLOW,
};

/** \ingroup asyncio
 * libusb_transfer.flags values */
enum libusb_transfer_flags {
	/** Report short frames as errors */
	LIBUSB_TRANSFER_SHORT_NOT_OK = 1<<0,

	/** Automatically free() transfer buffer during libusb_free_transfer() */
	LIBUSB_TRANSFER_FREE_BUFFER = 1<<1,

	/** Automatically call libusb_free_transfer() after callback returns.
	 * If this flag is set, it is illegal to call libusb_free_transfer()
	 * from your transfer callback, as this will result in a double-free
	 * when this flag is acted upon. */
	LIBUSB_TRANSFER_FREE_TRANSFER = 1<<2,

	/** Terminate transfers that are a multiple of the endpoint's
	 * wMaxPacketSize with an extra zero length packet. This is useful
	 * when a device protocol mandates that each logical request is
	 * terminated by an incomplete packet (i.e. the logical requests are
	 * not separated by other means).
	 *
	 * This flag only affects host-to-device transfers to bulk and interrupt
	 * endpoints. In other situations, it is ignored.
	 *
	 * This flag only affects transfers with a length that is a multiple of
	 * the endpoint's wMaxPacketSize. On transfers of other lengths, this
	 * flag has no effect. Therefore, if you are working with a device that
	 * needs a ZLP whenever the end of the logical request falls on a packet
	 * boundary, then it is sensible to set this flag on <em>every</em>
	 * transfer (you do not have to worry about only setting it on transfers
	 * that end on the boundary).
	 *
	 * This flag is currently only supported on Linux.
	 * On other systems, libusb_submit_transfer() will return
	 * LIBUSB_ERROR_NOT_SUPPORTED for every transfer where this flag is set.
	 *
	 * Available since libusb-1.0.9.
	 */
	LIBUSB_TRANSFER_ADD_ZERO_PACKET = 1 << 3,
};

/** \ingroup asyncio
 * Isochronous packet descriptor. */
struct libusb_iso_packet_descriptor {
	/** Length of data to request in this packet */
	unsigned int length;

	/** Amount of data that was actually transferred */
	unsigned int actual_length;

	/** Status code for this packet */
	enum libusb_transfer_status status;
};

struct libusb_transfer;

/** \ingroup asyncio
 * Asynchronous transfer callback function type. When submitting asynchronous
 * transfers, you pass a pointer to a callback function of this type via the
 * \ref libusb_transfer::callback "callback" member of the libusb_transfer
 * structure. libusb will call this function later, when the transfer has
 * completed or failed. See \ref asyncio for more information.
 * \param transfer The libusb_transfer struct the callback function is being
 * notified about.
 */
typedef void (LIBUSB_CALL *libusb_transfer_cb_fn)(struct libusb_transfer *transfer);

/** \ingroup asyncio
 * The generic USB transfer structure. The user populates this structure and
 * then submits it in order to request a transfer. After the transfer has
 * completed, the library populates the transfer with the results and passes
 * it back to the user.
 */
struct libusb_transfer {
	/** Handle of the device that this transfer will be submitted to */
	libusb_device_handle *dev_handle;

	/** A bitwise OR combination of \ref libusb_transfer_flags. */
	uint8_t flags;

	/** Address of the endpoint where this transfer will be sent. */
	unsigned char endpoint;

	/** Type of the endpoint from \ref libusb_transfer_type */
	unsigned char type;

	/** Timeout for this transfer in millseconds. A value of 0 indicates no
	 * timeout. */
	unsigned int timeout;

	/** The status of the transfer. Read-only, and only for use within
	 * transfer callback function.
	 *
	 * If this is an isochronous transfer, this field may read COMPLETED even
	 * if there were errors in the frames. Use the
	 * \ref libusb_iso_packet_descriptor::status "status" field in each packet
	 * to determine if errors occurred. */
	enum libusb_transfer_status status;

	/** Length of the data buffer */
	int length;

	/** Actual length of data that was transferred. Read-only, and only for
	 * use within transfer callback function. Not valid for isochronous
	 * endpoint transfers. */
	int actual_length;

	/** Callback function. This will be invoked when the transfer completes,
	 * fails, or is cancelled. */
	libusb_transfer_cb_fn callback;

	/** User context data to pass to the callback function. */
	void *user_data;

	/** Data buffer */
	unsigned char *buffer;

	/** Number of isochronous packets. Only used for I/O with isochronous
	 * endpoints. */
	int num_iso_packets;

	/** Isochronous packet descriptors, for isochronous transfers only. */
	struct libusb_iso_packet_descriptor iso_packet_desc
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
	[] /* valid C99 code */
#else
	[0] /* non-standard, but usually working code */
#endif
	;
};

/** \ingroup misc
 * Capabilities supported by this instance of libusb. Test if the loaded
 * library supports a given capability by calling
 * \ref libusb_has_capability().
 */
enum libusb_capability {
	/** The libusb_has_capability() API is available. */
	LIBUSB_CAP_HAS_CAPABILITY = 0,
};

int LIBUSB_CALL libusb_init(libusb_context **ctx);
void LIBUSB_CALL libusb_exit(libusb_context *ctx);
void LIBUSB_CALL libusb_set_debug(libusb_context *ctx, int level);
const struct libusb_version * LIBUSB_CALL libusb_get_version(void);
int LIBUSB_CALL libusb_has_capability(uint32_t capability);
const char * LIBUSB_CALL libusb_error_name(int errcode);

ssize_t LIBUSB_CALL libusb_get_device_list(libusb_context *ctx,
	libusb_device ***list);
void LIBUSB_CALL libusb_free_device_list(libusb_device **list,
	int unref_devices);
libusb_device * LIBUSB_CALL libusb_ref_device(libusb_device *dev);
void LIBUSB_CALL libusb_unref_device(libusb_device *dev);

int LIBUSB_CALL libusb_get_configuration(libusb_device_handle *dev,
	int *config);
int LIBUSB_CALL libusb_get_device_descriptor(libusb_device *dev,
	struct libusb_device_descriptor *desc);
int LIBUSB_CALL libusb_get_active_config_descriptor(libusb_device *dev,
	struct libusb_config_descriptor **config);
int LIBUSB_CALL libusb_get_config_descriptor(libusb_device *dev,
	uint8_t config_index, struct libusb_config_descriptor **config);
int LIBUSB_CALL libusb_get_config_descriptor_by_value(libusb_device *dev,
	uint8_t bConfigurationValue, struct libusb_config_descriptor **config);
void LIBUSB_CALL libusb_free_config_descriptor(
	struct libusb_config_descriptor *config);
uint8_t LIBUSB_CALL libusb_get_bus_number(libusb_device *dev);
uint8_t LIBUSB_CALL libusb_get_device_address(libusb_device *dev);
int LIBUSB_CALL libusb_get_device_speed(libusb_device *dev);
int LIBUSB_CALL libusb_get_max_packet_size(libusb_device *dev,
	unsigned char endpoint);
int LIBUSB_CALL libusb_get_max_iso_packet_size(libusb_device *dev,
	unsigned char endpoint);

int LIBUSB_CALL libusb_open(libusb_device *dev, libusb_device_handle **handle);
void LIBUSB_CALL libusb_close(libusb_device_handle *dev_handle);
libusb_device * LIBUSB_CALL libusb_get_device(libusb_device_handle *dev_handle);

int LIBUSB_CALL libusb_set_configuration(libusb_device_handle *dev,
	int configuration);
int LIBUSB_CALL libusb_claim_interface(libusb_device_handle *dev,
	int interface_number);
int LIBUSB_CALL libusb_release_interface(libusb_device_handle *dev,
	int interface_number);

libusb_device_handle * LIBUSB_CALL libusb_open_device_with_vid_pid(
	libusb_context *ctx, uint16_t vendor_id, uint16_t product_id);

int LIBUSB_CALL libusb_set_interface_alt_setting(libusb_device_handle *dev,
	int interface_number, int alternate_setting);
int LIBUSB_CALL libusb_clear_halt(libusb_device_handle *dev,
	unsigned char endpoint);
int LIBUSB_CALL libusb_reset_device(libusb_device_handle *dev);

int LIBUSB_CALL libusb_kernel_driver_active(libusb_device_handle *dev,
	int interface_number);
int LIBUSB_CALL libusb_detach_kernel_driver(libusb_device_handle *dev,
	int interface_number);
int LIBUSB_CALL libusb_attach_kernel_driver(libusb_device_handle *dev,
	int interface_number);

/* async I/O */

/** \ingroup asyncio
 * Get the data section of a control transfer. This convenience function is here
 * to remind you that the data does not start until 8 bytes into the actual
 * buffer, as the setup packet comes first.
 *
 * Calling this function only makes sense from a transfer callback function,
 * or situations where you have already allocated a suitably sized buffer at
 * transfer->buffer.
 *
 * \param transfer a transfer
 * \returns pointer to the first byte of the data section
 */
static inline unsigned char *libusb_control_transfer_get_data(
	struct libusb_transfer *transfer)
{
	return transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE;
}

/** \ingroup asyncio
 * Get the control setup packet of a control transfer. This convenience
 * function is here to remind you that the control setup occupies the first
 * 8 bytes of the transfer data buffer.
 *
 * Calling this function only makes sense from a transfer callback function,
 * or situations where you have already allocated a suitably sized buffer at
 * transfer->buffer.
 *
 * \param transfer a transfer
 * \returns a casted pointer to the start of the transfer data buffer
 */
static inline struct libusb_control_setup *libusb_control_transfer_get_setup(
	struct libusb_transfer *transfer)
{
	return (struct libusb_control_setup *) transfer->buffer;
}

/** \ingroup asyncio
 * Helper function to populate the setup packet (first 8 bytes of the data
 * buffer) for a control transfer. The wIndex, wValue and wLength values should
 * be given in host-endian byte order.
 *
 * \param buffer buffer to output the setup packet into
 * \param bmRequestType see the
 * \ref libusb_control_setup::bmRequestType "bmRequestType" field of
 * \ref libusb_control_setup
 * \param bRequest see the
 * \ref libusb_control_setup::bRequest "bRequest" field of
 * \ref libusb_control_setup
 * \param wValue see the
 * \ref libusb_control_setup::wValue "wValue" field of
 * \ref libusb_control_setup
 * \param wIndex see the
 * \ref libusb_control_setup::wIndex "wIndex" field of
 * \ref libusb_control_setup
 * \param wLength see the
 * \ref libusb_control_setup::wLength "wLength" field of
 * \ref libusb_control_setup
 */
static inline void libusb_fill_control_setup(unsigned char *buffer,
	uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
	uint16_t wLength)
{
	struct libusb_control_setup *setup = (struct libusb_control_setup *) buffer;
	setup->bmRequestType = bmRequestType;
	setup->bRequest = bRequest;
	setup->wValue = libusb_cpu_to_le16(wValue);
	setup->wIndex = libusb_cpu_to_le16(wIndex);
	setup->wLength = libusb_cpu_to_le16(wLength);
}

struct libusb_transfer * LIBUSB_CALL libusb_alloc_transfer(int iso_packets);
int LIBUSB_CALL libusb_submit_transfer(struct libusb_transfer *transfer);
int LIBUSB_CALL libusb_cancel_transfer(struct libusb_transfer *transfer);
void LIBUSB_CALL libusb_free_transfer(struct libusb_transfer *transfer);

/** \ingroup asyncio
 * Helper function to populate the required \ref libusb_transfer fields
 * for a control transfer.
 *
 * If you pass a transfer buffer to this function, the first 8 bytes will
 * be interpreted as a control setup packet, and the wLength field will be
 * used to automatically populate the \ref libusb_transfer::length "length"
 * field of the transfer. Therefore the recommended approach is:
 * -# Allocate a suitably sized data buffer (including space for control setup)
 * -# Call libusb_fill_control_setup()
 * -# If this is a host-to-device transfer with a data stage, put the data
 *    in place after the setup packet
 * -# Call this function
 * -# Call libusb_submit_transfer()
 *
 * It is also legal to pass a NULL buffer to this function, in which case this
 * function will not attempt to populate the length field. Remember that you
 * must then populate the buffer and length fields later.
 *
 * \param transfer the transfer to populate
 * \param dev_handle handle of the device that will handle the transfer
 * \param buffer data buffer. If provided, this function will interpret the
 * first 8 bytes as a setup packet and infer the transfer length from that.
 * \param callback callback function to be invoked on transfer completion
 * \param user_data user data to pass to callback function
 * \param timeout timeout for the transfer in milliseconds
 */
static inline void libusb_fill_control_transfer(
	struct libusb_transfer *transfer, libusb_device_handle *dev_handle,
	unsigned char *buffer, libusb_transfer_cb_fn callback, void *user_data,
	unsigned int timeout)
{
	struct libusb_control_setup *setup = (struct libusb_control_setup *) buffer;
	transfer->dev_handle = dev_handle;
	transfer->endpoint = 0;
	transfer->type = LIBUSB_TRANSFER_TYPE_CONTROL;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	if (setup)
		transfer->length = LIBUSB_CONTROL_SETUP_SIZE
			+ libusb_le16_to_cpu(setup->wLength);
	transfer->user_data = user_data;
	transfer->callback = callback;
}

/** \ingroup asyncio
 * Helper function to populate the required \ref libusb_transfer fields
 * for a bulk transfer.
 *
 * \param transfer the transfer to populate
 * \param dev_handle handle of the device that will handle the transfer
 * \param endpoint address of the endpoint where this transfer will be sent
 * \param buffer data buffer
 * \param length length of data buffer
 * \param callback callback function to be invoked on transfer completion
 * \param user_data user data to pass to callback function
 * \param timeout timeout for the transfer in milliseconds
 */
static inline void libusb_fill_bulk_transfer(struct libusb_transfer *transfer,
	libusb_device_handle *dev_handle, unsigned char endpoint,
	unsigned char *buffer, int length, libusb_transfer_cb_fn callback,
	void *user_data, unsigned int timeout)
{
	transfer->dev_handle = dev_handle;
	transfer->endpoint = endpoint;
	transfer->type = LIBUSB_TRANSFER_TYPE_BULK;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	transfer->length = length;
	transfer->user_data = user_data;
	transfer->callback = callback;
}

/** \ingroup asyncio
 * Helper function to populate the required \ref libusb_transfer fields
 * for an interrupt transfer.
 *
 * \param transfer the transfer to populate
 * \param dev_handle handle of the device that will handle the transfer
 * \param endpoint address of the endpoint where this transfer will be sent
 * \param buffer data buffer
 * \param length length of data buffer
 * \param callback callback function to be invoked on transfer completion
 * \param user_data user data to pass to callback function
 * \param timeout timeout for the transfer in milliseconds
 */
static inline void libusb_fill_interrupt_transfer(
	struct libusb_transfer *transfer, libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *buffer, int length,
	libusb_transfer_cb_fn callback, void *user_data, unsigned int timeout)
{
	transfer->dev_handle = dev_handle;
	transfer->endpoint = endpoint;
	transfer->type = LIBUSB_TRANSFER_TYPE_INTERRUPT;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	transfer->length = length;
	transfer->user_data = user_data;
	transfer->callback = callback;
}

/** \ingroup asyncio
 * Helper function to populate the required \ref libusb_transfer fields
 * for an isochronous transfer.
 *
 * \param transfer the transfer to populate
 * \param dev_handle handle of the device that will handle the transfer
 * \param endpoint address of the endpoint where this transfer will be sent
 * \param buffer data buffer
 * \param length length of data buffer
 * \param num_iso_packets the number of isochronous packets
 * \param callback callback function to be invoked on transfer completion
 * \param user_data user data to pass to callback function
 * \param timeout timeout for the transfer in milliseconds
 */
static inline void libusb_fill_iso_transfer(struct libusb_transfer *transfer,
	libusb_device_handle *dev_handle, unsigned char endpoint,
	unsigned char *buffer, int length, int num_iso_packets,
	libusb_transfer_cb_fn callback, void *user_data, unsigned int timeout)
{
	transfer->dev_handle = dev_handle;
	transfer->endpoint = endpoint;
	transfer->type = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	transfer->length = length;
	transfer->num_iso_packets = num_iso_packets;
	transfer->user_data = user_data;
	transfer->callback = callback;
}

/** \ingroup asyncio
 * Convenience function to set the length of all packets in an isochronous
 * transfer, based on the num_iso_packets field in the transfer structure.
 *
 * \param transfer a transfer
 * \param length the length to set in each isochronous packet descriptor
 * \see libusb_get_max_packet_size()
 */
static inline void libusb_set_iso_packet_lengths(
	struct libusb_transfer *transfer, unsigned int length)
{
	int i;
	for (i = 0; i < transfer->num_iso_packets; i++)
		transfer->iso_packet_desc[i].length = length;
}

/** \ingroup asyncio
 * Convenience function to locate the position of an isochronous packet
 * within the buffer of an isochronous transfer.
 *
 * This is a thorough function which loops through all preceding packets,
 * accumulating their lengths to find the position of the specified packet.
 * Typically you will assign equal lengths to each packet in the transfer,
 * and hence the above method is sub-optimal. You may wish to use
 * libusb_get_iso_packet_buffer_simple() instead.
 *
 * \param transfer a transfer
 * \param packet the packet to return the address of
 * \returns the base address of the packet buffer inside the transfer buffer,
 * or NULL if the packet does not exist.
 * \see libusb_get_iso_packet_buffer_simple()
 */
static inline unsigned char *libusb_get_iso_packet_buffer(
	struct libusb_transfer *transfer, unsigned int packet)
{
	int i;
	size_t offset = 0;
	int _packet;

	/* oops..slight bug in the API. packet is an unsigned int, but we use
	 * signed integers almost everywhere else. range-check and convert to
	 * signed to avoid compiler warnings. FIXME for libusb-2. */
	if (packet > INT_MAX)
		return NULL;
	_packet = packet;

	if (_packet >= transfer->num_iso_packets)
		return NULL;

	for (i = 0; i < _packet; i++)
		offset += transfer->iso_packet_desc[i].length;

	return transfer->buffer + offset;
}

/** \ingroup asyncio
 * Convenience function to locate the position of an isochronous packet
 * within the buffer of an isochronous transfer, for transfers where each
 * packet is of identical size.
 *
 * This function relies on the assumption that every packet within the transfer
 * is of identical size to the first packet. Calculating the location of
 * the packet buffer is then just a simple calculation:
 * <tt>buffer + (packet_size * packet)</tt>
 *
 * Do not use this function on transfers other than those that have identical
 * packet lengths for each packet.
 *
 * \param transfer a transfer
 * \param packet the packet to return the address of
 * \returns the base address of the packet buffer inside the transfer buffer,
 * or NULL if the packet does not exist.
 * \see libusb_get_iso_packet_buffer()
 */
static inline unsigned char *libusb_get_iso_packet_buffer_simple(
	struct libusb_transfer *transfer, unsigned int packet)
{
	int _packet;

	/* oops..slight bug in the API. packet is an unsigned int, but we use
	 * signed integers almost everywhere else. range-check and convert to
	 * signed to avoid compiler warnings. FIXME for libusb-2. */
	if (packet > INT_MAX)
		return NULL;
	_packet = packet;

	if (_packet >= transfer->num_iso_packets)
		return NULL;

	return transfer->buffer + (transfer->iso_packet_desc[0].length * _packet);
}

/* sync I/O */

int LIBUSB_CALL libusb_control_transfer(libusb_device_handle *dev_handle,
	uint8_t request_type, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
	unsigned char *data, uint16_t wLength, unsigned int timeout);

int LIBUSB_CALL libusb_bulk_transfer(libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *data, int length,
	int *actual_length, unsigned int timeout);

int LIBUSB_CALL libusb_interrupt_transfer(libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *data, int length,
	int *actual_length, unsigned int timeout);

/** \ingroup desc
 * Retrieve a descriptor from the default control pipe.
 * This is a convenience function which formulates the appropriate control
 * message to retrieve the descriptor.
 *
 * \param dev a device handle
 * \param desc_type the descriptor type, see \ref libusb_descriptor_type
 * \param desc_index the index of the descriptor to retrieve
 * \param data output buffer for descriptor
 * \param length size of data buffer
 * \returns number of bytes returned in data, or LIBUSB_ERROR code on failure
 */
static inline int libusb_get_descriptor(libusb_device_handle *dev,
	uint8_t desc_type, uint8_t desc_index, unsigned char *data, int length)
{
	return libusb_control_transfer(dev, LIBUSB_ENDPOINT_IN,
		LIBUSB_REQUEST_GET_DESCRIPTOR, (desc_type << 8) | desc_index, 0, data,
		(uint16_t) length, 1000);
}

/** \ingroup desc
 * Retrieve a descriptor from a device.
 * This is a convenience function which formulates the appropriate control
 * message to retrieve the descriptor. The string returned is Unicode, as
 * detailed in the USB specifications.
 *
 * \param dev a device handle
 * \param desc_index the index of the descriptor to retrieve
 * \param langid the language ID for the string descriptor
 * \param data output buffer for descriptor
 * \param length size of data buffer
 * \returns number of bytes returned in data, or LIBUSB_ERROR code on failure
 * \see libusb_get_string_descriptor_ascii()
 */
static inline int libusb_get_string_descriptor(libusb_device_handle *dev,
	uint8_t desc_index, uint16_t langid, unsigned char *data, int length)
{
	return libusb_control_transfer(dev, LIBUSB_ENDPOINT_IN,
		LIBUSB_REQUEST_GET_DESCRIPTOR, (uint16_t)((LIBUSB_DT_STRING << 8) | desc_index),
		langid, data, (uint16_t) length, 1000);
}

int LIBUSB_CALL libusb_get_string_descriptor_ascii(libusb_device_handle *dev,
	uint8_t desc_index, unsigned char *data, int length);

/* polling and timeouts */

int LIBUSB_CALL libusb_try_lock_events(libusb_context *ctx);
void LIBUSB_CALL libusb_lock_events(libusb_context *ctx);
void LIBUSB_CALL libusb_unlock_events(libusb_context *ctx);
int LIBUSB_CALL libusb_event_handling_ok(libusb_context *ctx);
int LIBUSB_CALL libusb_event_handler_active(libusb_context *ctx);
void LIBUSB_CALL libusb_lock_event_waiters(libusb_context *ctx);
void LIBUSB_CALL libusb_unlock_event_waiters(libusb_context *ctx);
int LIBUSB_CALL libusb_wait_for_event(libusb_context *ctx, struct timeval *tv);

int LIBUSB_CALL libusb_handle_events_timeout(libusb_context *ctx,
	struct timeval *tv);
int LIBUSB_CALL libusb_handle_events_timeout_completed(libusb_context *ctx,
	struct timeval *tv, int *completed);
int LIBUSB_CALL libusb_handle_events(libusb_context *ctx);
int LIBUSB_CALL libusb_handle_events_completed(libusb_context *ctx, int *completed);
int LIBUSB_CALL libusb_handle_events_locked(libusb_context *ctx,
	struct timeval *tv);
int LIBUSB_CALL libusb_pollfds_handle_timeouts(libusb_context *ctx);
int LIBUSB_CALL libusb_get_next_timeout(libusb_context *ctx,
	struct timeval *tv);

/** \ingroup poll
 * File descriptor for polling
 */
struct libusb_pollfd {
	/** Numeric file descriptor */
	int fd;

	/** Event flags to poll for from <poll.h>. POLLIN indicates that you
	 * should monitor this file descriptor for becoming ready to read from,
	 * and POLLOUT indicates that you should monitor this file descriptor for
	 * nonblocking write readiness. */
	short events;
};

/** \ingroup poll
 * Callback function, invoked when a new file descriptor should be added
 * to the set of file descriptors monitored for events.
 * \param fd the new file descriptor
 * \param events events to monitor for, see \ref libusb_pollfd for a
 * description
 * \param user_data User data pointer specified in
 * libusb_set_pollfd_notifiers() call
 * \see libusb_set_pollfd_notifiers()
 */
typedef void (LIBUSB_CALL *libusb_pollfd_added_cb)(int fd, short events,
	void *user_data);

/** \ingroup poll
 * Callback function, invoked when a file descriptor should be removed from
 * the set of file descriptors being monitored for events. After returning
 * from this callback, do not use that file descriptor again.
 * \param fd the file descriptor to stop monitoring
 * \param user_data User data pointer specified in
 * libusb_set_pollfd_notifiers() call
 * \see libusb_set_pollfd_notifiers()
 */
typedef void (LIBUSB_CALL *libusb_pollfd_removed_cb)(int fd, void *user_data);

const struct libusb_pollfd ** LIBUSB_CALL libusb_get_pollfds(
	libusb_context *ctx);
void LIBUSB_CALL libusb_set_pollfd_notifiers(libusb_context *ctx,
	libusb_pollfd_added_cb added_cb, libusb_pollfd_removed_cb removed_cb,
	void *user_data);

#ifdef __cplusplus
}
#endif

#endif
