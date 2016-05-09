#ifndef LIBUSBI_H
#define LIBUSBI_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <poll.h>
#include <sys/types.h>
#include <limits.h>

#include "common.h"


enum libusb_error {
	LIBUSB_SUCCESS = 0,
	LIBUSB_ERROR_IO = -1,
	LIBUSB_ERROR_INVALID_PARAM = -2,
	LIBUSB_ERROR_ACCESS = -3,
	LIBUSB_ERROR_NO_DEVICE = -4,
	LIBUSB_ERROR_NOT_FOUND = -5,
	LIBUSB_ERROR_BUSY = -6,
	LIBUSB_ERROR_TIMEOUT = -7,
	LIBUSB_ERROR_OVERFLOW = -8,
	LIBUSB_ERROR_PIPE = -9,
	LIBUSB_ERROR_INTERRUPTED = -10,
	LIBUSB_ERROR_NO_MEM = -11,
	LIBUSB_ERROR_NOT_SUPPORTED = -12,
	LIBUSB_ERROR_OTHER = -99,
};

enum libusb_transfer_status {
	LIBUSB_TRANSFER_COMPLETED,
	LIBUSB_TRANSFER_ERROR,
	LIBUSB_TRANSFER_TIMED_OUT,
	LIBUSB_TRANSFER_CANCELLED,
	LIBUSB_TRANSFER_STALL,
	LIBUSB_TRANSFER_NO_DEVICE,
	LIBUSB_TRANSFER_OVERFLOW,
};

enum libusb_transfer_flags {
	LIBUSB_TRANSFER_SHORT_NOT_OK = 1<<0,
	LIBUSB_TRANSFER_FREE_BUFFER = 1<<1,
	LIBUSB_TRANSFER_FREE_TRANSFER = 1<<2,
	LIBUSB_TRANSFER_ADD_ZERO_PACKET = 1 << 3,
};
enum {
  USBI_CLOCK_MONOTONIC,
  USBI_CLOCK_REALTIME
};

int  libusb_init(libusb_context **ctx);
void  libusb_exit(libusb_context *ctx);
void  libusb_set_debug(libusb_context *ctx, int level);
const struct libusb_version *  libusb_get_version(void);
int  libusb_has_capability(uint32_t capability);
const char *  libusb_error_name(int errcode);

ssize_t  libusb_get_device_list(libusb_context *ctx,
	libusb_device ***list);
void  libusb_free_device_list(libusb_device **list,
	int unref_devices);
//libusb_device *libusb_ref_device(libusb_device *dev);
//void  libusb_unref_device(libusb_device *dev);

int  libusb_get_configuration(libusb_device_handle *dev,
	int *config);
int  libusb_get_device_descriptor(libusb_device *dev,
	struct libusb_device_descriptor *desc);
int  libusb_get_active_config_descriptor(libusb_device *dev,
	struct libusb_config_descriptor **config);
int  libusb_get_config_descriptor(libusb_device *dev,
	uint8_t config_index, struct libusb_config_descriptor **config);
int  libusb_get_config_descriptor_by_value(libusb_device *dev,
	uint8_t bConfigurationValue, struct libusb_config_descriptor **config);
void  libusb_free_config_descriptor(
	struct libusb_config_descriptor *config);
uint8_t  libusb_get_bus_number(libusb_device *dev);
uint8_t  libusb_get_device_address(libusb_device *dev);
int  libusb_get_device_speed(libusb_device *dev);
int  libusb_get_max_packet_size(libusb_device *dev,
	unsigned char endpoint);
int  libusb_get_max_iso_packet_size(libusb_device *dev,
	unsigned char endpoint);

int  libusb_open(libusb_device *dev, libusb_device_handle **handle);
void  libusb_close(libusb_device_handle *dev_handle);
libusb_device *  libusb_get_device(libusb_device_handle *dev_handle);

int  libusb_set_configuration(libusb_device_handle *dev,
	int configuration);
int  libusb_claim_interface(libusb_device_handle *dev,
	int interface_number);
int  libusb_release_interface(libusb_device_handle *dev,
	int interface_number);

libusb_device_handle *  libusb_open_device_with_vid_pid(
	libusb_context *ctx, uint16_t vendor_id, uint16_t product_id);

int  libusb_set_interface_alt_setting(libusb_device_handle *dev,
	int interface_number, int alternate_setting);
int  libusb_clear_halt(libusb_device_handle *dev,
	unsigned char endpoint);
int  libusb_reset_device(libusb_device_handle *dev);

int  libusb_kernel_driver_active(libusb_device_handle *dev,
	int interface_number);
int  libusb_detach_kernel_driver(libusb_device_handle *dev,
	int interface_number);
int  libusb_attach_kernel_driver(libusb_device_handle *dev,
	int interface_number);


struct libusb_transfer *libusb_alloc_transfer(int iso_packets);
void  libusb_free_transfer(struct libusb_transfer *transfer);
int  libusb_submit_transfer(struct libusb_transfer *transfer);
int  libusb_cancel_transfer(struct libusb_transfer *transfer);
void  libusb_free_transfer(struct libusb_transfer *transfer);


int  libusb_bulk_transfer(libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *data, int length,
	int *actual_length, unsigned int timeout);

int  libusb_interrupt_transfer(libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *data, int length,
	int *actual_length, unsigned int timeout);


int  libusb_get_string_descriptor_ascii(libusb_device_handle *dev,
	uint8_t desc_index, unsigned char *data, int length);

int libusb_show_device(uint16_t vendor_id, uint16_t product_id);
int libusb_show_all_devices();

#endif

