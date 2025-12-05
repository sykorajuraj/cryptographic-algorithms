/**
 * @file utils/utils.h
 * @brief Utility functions for demonstrations and testing
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Colors for terminal output
#define COLOR_CYAN "\033[0;36m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_RED "\033[0;31m"
#define COLOR_BLUE "\033[0;34m"
#define COLOR_MAGENTA "\033[0;35m"
#define COLOR_RESET "\033[0m"

// Box drawing constants
#define BOX_WIDTH 50

/**
 * Get time in microseconds
 * @return Time in microseconds (double format)
 */
double get_time_us(void);

/**
 * @brief Print a horizontal line for box borders
 * @param width Width of the box (internal width, excluding border characters)
 * @param top_border If true, prints top border; if false, prints bottom border
 */
void print_box_line(int width, int top_border);

/**
 * @brief Print a text line centered within a box
 * @param text Text to print
 * @param width Width of the box (internal width)
 */
void print_box_text(const char *text, int width);

/**
 * @brief Print a complete box with title
 * @param title Title text to display in the box
 * @param width Width of the box (internal width)
 * @param color Color code (use COLOR_* defines, or NULL for no color)
 */
void print_box(const char *title, int width, const char *color);

/**
 * @brief Print a section header box
 * @param title Title text
 * @param width Width of the box
 */
void print_section_box(const char *title, int width);

/**
 * @brief Print a success message box
 * @param message Message text
 * @param width Width of the box
 */
void print_success_box(const char *message, int width);

/**
 * @brief Print an error message box
 * @param message Error message text
 * @param width Width of the box
 */
void print_error_box(const char *message, int width);

/**
 * @brief Print hex dump of data
 * @param label Label to print before data
 * @param data Pointer to data
 * @param len Length of data in bytes
 */
void print_hex(const char *label, const uint8_t *data, size_t len);

/**
 * @brief Print hex dump with line wrapping
 * @param label Label to print before data
 * @param data Pointer to data
 * @param len Length of data in bytes
 * @param bytes_per_line Number of bytes to print per line
 */
void print_hex_wrapped(const char *label, const uint8_t *data, size_t len, int bytes_per_line);

/**
 * @brief Generate random bytes
 * @param buffer Buffer to fill
 * @param len Number of bytes to generate
 */
void generate_random_bytes(uint8_t *buffer, size_t len);

#ifdef __cplusplus
}
#endif

#endif // UTILS_H