/**
 * @file utils/utils.c
 * @brief Utility functions for demonstrations and testing
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "utils.h"

/**
 * Get time in microseconds
 */
double get_time_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000000.0 + (double)tv.tv_usec;
}

/**
 * Print a horizontal line for box borders
 */
void print_box_line(int width, int top_border) {
    if (top_border) {
        printf("╔");
        for (int i = 0; i < width; i++) printf("═");
        printf("╗\n");
    } else {
        printf("╚");
        for (int i = 0; i < width; i++) printf("═");
        printf("╝\n");
    }
}

/**
 * Print a text line centered within a box
 */
void print_box_text(const char *text, int width) {
    int text_len = strlen(text);
    int padding = (width - text_len) / 2;
    int right_padding = width - text_len - padding;
    
    printf("║");
    for (int i = 0; i < padding; i++) printf(" ");
    printf("%s", text);
    for (int i = 0; i < right_padding; i++) printf(" ");
    printf("║\n");
}

/**
 * Print a complete box with title
 */
void print_box(const char *title, int width, const char *color) {
    if (color) printf("%s", color);
    
    printf("\n");
    print_box_line(width, 1);  // Top border
    print_box_text("", width);  // Empty line
    print_box_text(title, width);  // Title
    print_box_text("", width);  // Empty line
    print_box_line(width, 0);  // Bottom border
    
    if (color) printf(COLOR_RESET);
}

/**
 * Print a simple section header box
 */
void print_section_box(const char *title, int width) {
    print_box(title, width, COLOR_CYAN);
}

/**
 * Print a completion/success message box
 */
void print_success_box(const char *message, int width) {
    print_box(message, width, COLOR_GREEN);
}

/**
 * Print an error message box
 */
void print_error_box(const char *message, int width) {
    print_box(message, width, COLOR_RED);
}

/**
 * @brief Print hex dump of data
 * @param label Label to print before data
 * @param data Pointer to data
 * @param len Length of data in bytes
 */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i < len - 1) printf(" ");
    }
    printf("\n");
}

/**
 * @brief Print hex dump with line wrapping
 * @param label Label to print before data
 * @param data Pointer to data
 * @param len Length of data in bytes
 * @param bytes_per_line Number of bytes to print per line
 */
void print_hex_wrapped(const char *label, const uint8_t *data, size_t len, int bytes_per_line) {
    printf("%s", label);
    
    for (size_t i = 0; i < len; i++) {
        if (i > 0 && i % bytes_per_line == 0) {
            printf("\n");
            // Print spaces for indentation matching label length
            for (size_t j = 0; j < strlen(label); j++) {
                printf(" ");
            }
        }
        printf("%02x", data[i]);
        if (i < len - 1) printf(" ");
    }
    printf("\n");
}

/**
 * @brief Generate random bytes
 * @param buffer Buffer to fill
 * @param len Number of bytes to generate
 */
void generate_random_bytes(uint8_t *buffer, size_t len) {
    static int seeded = 0;
    
    if (!seeded) {
        srand(time(NULL));
        seeded = 1;
    }
    
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(rand() % 256);
    }
}