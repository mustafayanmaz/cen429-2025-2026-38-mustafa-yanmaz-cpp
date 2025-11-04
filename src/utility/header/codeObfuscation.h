/**
 * @file codeObfuscation.h
 * @brief Advanced code obfuscation and hardening techniques
 * @details Implements various obfuscation techniques including:
 *          - Opaque predicates
 *          - Control flow obfuscation
 *          - Arithmetic obfuscation (MBA)
 *          - String obfuscation
 *          - Function parameter encoding
 *          - Dead code injection
 */

#ifndef CODE_OBFUSCATION_H
#define CODE_OBFUSCATION_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// OPAQUE PREDICATES - Always true/false but hard to analyze
// ============================================================================

/**
 * @brief Opaque predicate that always returns true
 * @details Uses mathematical property: (x^2 + x) is always even
 */
static inline int opaque_true(int x) {
    volatile int a = x * x + x;
    volatile int b = 2;
    return (a % b) == 0;
}

/**
 * @brief Opaque predicate that always returns false
 * @details Uses mathematical property: (x^2 + x) % 2 can never be 1
 */
static inline int opaque_false(int x) {
    volatile int a = x * x + x;
    volatile int b = 2;
    return (a % b) == 1;
}

/**
 * @brief Complex opaque predicate using multiple operations
 */
static inline int opaque_complex(int x, int y) {
    volatile int result = ((x * x) - (y * y)) == ((x + y) * (x - y));
    return result;
}

// ============================================================================
// ARITHMETIC OBFUSCATION - Mixed Boolean-Arithmetic (MBA)
// ============================================================================

/**
 * @brief Obfuscated addition: a + b
 * @details Uses MBA: a + b = (a ^ b) + 2 * (a & b)
 */
static inline int obf_add(int a, int b) {
    volatile int xor_part = a ^ b;
    volatile int and_part = a & b;
    volatile int shift_part = and_part << 1;
    return xor_part + shift_part;
}

/**
 * @brief Obfuscated subtraction: a - b
 */
static inline int obf_sub(int a, int b) {
    volatile int not_b = ~b + 1;
    return obf_add(a, not_b);
}

/**
 * @brief Obfuscated multiplication by constant
 */
static inline int obf_mul_const(int x, int c) {
    volatile int result = 0;
    volatile int temp = x;
    volatile int multiplier = c;
    
    while (multiplier > 0) {
        if (multiplier & 1) {
            result = obf_add(result, temp);
        }
        temp = temp << 1;
        multiplier = multiplier >> 1;
    }
    return result;
}

/**
 * @brief Obfuscated comparison: returns 1 if a == b, 0 otherwise
 */
static inline int obf_equals(int a, int b) {
    volatile int diff = a ^ b;
    volatile int result = 1;
    
    // Opaque loop
    for (volatile int i = 0; i < 32; i++) {
        if (diff & (1 << i)) {
            result = 0;
        }
    }
    return result;
}

// ============================================================================
// OPAQUE LOOPS - Complex loops that are hard to analyze
// ============================================================================

/**
 * @brief Opaque loop that always executes exactly n iterations
 * @details Uses complex control flow to obscure iteration count
 */
static inline void opaque_loop_n(int n, void (*callback)(int)) {
    volatile int counter = 0;
    volatile int dummy = rand() | 1; // Always odd
    
    while (counter < n) {
        if (opaque_true(dummy)) {
            if (callback) callback(counter);
            counter = obf_add(counter, 1);
        }
        
        // Dead code that never executes
        if (opaque_false(dummy)) {
            counter = obf_sub(counter, 1);
        }
    }
}

/**
 * @brief Complex loop with opaque predicates
 */
static inline void opaque_loop_complex(int iterations) {
    volatile int i = 0;
    volatile int j = 0;
    volatile int dummy = rand() | 1;
    
    while (i < iterations) {
        if (opaque_true(dummy)) {
            j = obf_add(j, 1);
            
            // Nested opaque condition
            if (opaque_complex(i, j)) {
                i = obf_add(i, 1);
            }
        }
        
        // Fake branch
        if (opaque_false(dummy)) {
            i = obf_sub(i, 2);
            j = obf_mul_const(j, 3);
        }
    }
}

// ============================================================================
// STRING OBFUSCATION
// ============================================================================

/**
 * @brief Simple XOR-based string obfuscation
 */
static inline void obf_xor_string(char* str, size_t len, uint8_t key) {
    volatile uint8_t k = key;
    for (volatile size_t i = 0; i < len; i++) {
        if (opaque_true((int)i)) {
            str[i] ^= k;
            k = (k * 31 + 17) & 0xFF; // Evolving key
        }
    }
}

/**
 * @brief Compile-time string obfuscation helper
 */
#define OBF_STR_KEY 0xA5

/**
 * @brief Macro for obfuscated string literals
 * @details String is XOR'd at compile time and decoded at runtime
 */
#define OBFUSCATED_STRING(str) obf_decode_string(str, sizeof(str) - 1)

static inline char* obf_decode_string(const char* encoded, size_t len) {
    static char buffer[512];
    volatile size_t copy_len = (len < 511) ? len : 511;
    
    for (volatile size_t i = 0; i < copy_len; i++) {
        if (opaque_true((int)i)) {
            buffer[i] = encoded[i] ^ (OBF_STR_KEY + (i & 0xFF));
        }
    }
    buffer[copy_len] = '\0';
    return buffer;
}

// ============================================================================
// FUNCTION PARAMETER ENCODING
// ============================================================================

/**
 * @brief Encode function parameter
 */
static inline uint32_t encode_param(uint32_t param, uint32_t seed) {
    volatile uint32_t encoded = param ^ seed;
    encoded = (encoded << 7) | (encoded >> 25);
    encoded ^= 0xDEADBEEF;
    return encoded;
}

/**
 * @brief Decode function parameter
 */
static inline uint32_t decode_param(uint32_t encoded, uint32_t seed) {
    volatile uint32_t decoded = encoded ^ 0xDEADBEEF;
    decoded = (decoded >> 7) | (decoded << 25);
    decoded ^= seed;
    return decoded;
}

// ============================================================================
// CONTROL FLOW OBFUSCATION
// ============================================================================

/**
 * @brief Control flow dispatcher state
 */
typedef struct {
    volatile int state;
    volatile int next_state;
    volatile int dummy_state;
} CFDispatcher;

/**
 * @brief Initialize control flow dispatcher
 */
static inline void cf_init(CFDispatcher* disp, int initial_state) {
    disp->state = initial_state;
    disp->next_state = initial_state;
    disp->dummy_state = rand();
}

/**
 * @brief Transition to next state with obfuscation
 */
static inline void cf_transition(CFDispatcher* disp, int next) {
    volatile int dummy = rand() | 1;
    
    if (opaque_true(dummy)) {
        disp->state = next;
        disp->next_state = obf_add(next, 1);
    }
    
    // Fake transition
    if (opaque_false(dummy)) {
        disp->state = obf_mul_const(next, 2);
    }
}

/**
 * @brief Get current state with obfuscation
 */
static inline int cf_get_state(CFDispatcher* disp) {
    volatile int dummy = rand() | 1;
    volatile int result = disp->state;
    
    if (opaque_true(dummy)) {
        return result;
    }
    
    // Dead code
    return obf_mul_const(result, 0);
}

// ============================================================================
// DEAD CODE INJECTION
// ============================================================================

/**
 * @brief Inject dead code that appears useful but never executes
 */
static inline void inject_dead_code(int complexity) {
    volatile int dummy = rand() | 1;
    volatile int accumulator = 0;
    
    // This code never executes but looks meaningful
    if (opaque_false(dummy)) {
        for (volatile int i = 0; i < complexity; i++) {
            accumulator = obf_add(accumulator, i);
            accumulator = obf_mul_const(accumulator, 2);
            
            if (accumulator > 1000) {
                accumulator = obf_sub(accumulator, 500);
            }
        }
    }
}

/**
 * @brief Fake function that appears to do something but doesn't
 */
static inline int fake_operation(int a, int b, int c) {
    volatile int result = 0;
    volatile int dummy = rand() | 1;
    
    if (opaque_false(dummy)) {
        result = obf_add(a, b);
        result = obf_mul_const(result, c);
        result = obf_sub(result, a);
    }
    
    return result;
}

// ============================================================================
// STANDARD LIBRARY WRAPPERS (avoiding direct stdlib calls)
// ============================================================================

/**
 * @brief Obfuscated string copy
 */
static inline void obf_strcpy(char* dest, const char* src) {
    volatile size_t i = 0;
    volatile int dummy = rand() | 1;
    
    while (src[i] != '\0') {
        if (opaque_true(dummy)) {
            dest[i] = src[i];
            i = obf_add((int)i, 1);
        }
        
        // Dead branch
        if (opaque_false(dummy)) {
            dest[i] = src[i] ^ 0xFF;
        }
    }
    dest[i] = '\0';
}

/**
 * @brief Obfuscated memory copy
 */
static inline void obf_memcpy(void* dest, const void* src, size_t n) {
    volatile unsigned char* d = (unsigned char*)dest;
    volatile const unsigned char* s = (const unsigned char*)src;
    volatile size_t i = 0;
    volatile int dummy = rand() | 1;
    
    while (i < n) {
        if (opaque_true(dummy)) {
            d[i] = s[i];
            i = obf_add((int)i, 1);
        }
        
        inject_dead_code(2);
    }
}

/**
 * @brief Obfuscated string length
 */
static inline size_t obf_strlen(const char* str) {
    volatile size_t len = 0;
    volatile int dummy = rand() | 1;
    
    while (str[len] != '\0') {
        if (opaque_true(dummy)) {
            len = obf_add((int)len, 1);
        }
        
        // Fake operation
        if (opaque_false(dummy)) {
            len = obf_sub((int)len, 1);
        }
    }
    
    return len;
}

/**
 * @brief Obfuscated string compare
 */
static inline int obf_strcmp(const char* s1, const char* s2) {
    volatile size_t i = 0;
    volatile int dummy = rand() | 1;
    volatile int result = 0;
    
    while (s1[i] != '\0' || s2[i] != '\0') {
        if (opaque_true(dummy)) {
            volatile int diff = s1[i] - s2[i];
            if (diff != 0) {
                result = diff;
                break;
            }
            i = obf_add((int)i, 1);
        }
        
        inject_dead_code(1);
    }
    
    return result;
}

/**
 * @brief Obfuscated memory set
 */
static inline void obf_memset(void* ptr, int value, size_t num) {
    volatile unsigned char* p = (unsigned char*)ptr;
    volatile size_t i = 0;
    volatile int dummy = rand() | 1;
    
    while (i < num) {
        if (opaque_true(dummy)) {
            p[i] = (unsigned char)value;
            i = obf_add((int)i, 1);
        }
        
        // Dead branch
        if (opaque_false(dummy)) {
            p[i] = (unsigned char)(~value);
        }
    }
}

// ============================================================================
// RANDOM EXIT POINTS
// ============================================================================

/**
 * @brief Function with multiple obfuscated exit points
 * @return Always returns success (0) but through complex paths
 */
static inline int obf_multi_exit(int input) {
    volatile int result = 0;
    volatile int state = input % 4;
    volatile int dummy = rand() | 1;
    
    CFDispatcher disp;
    cf_init(&disp, state);
    
    while (1) {
        int current = cf_get_state(&disp);
        
        switch (current) {
            case 0:
                if (opaque_true(dummy)) {
                    result = 0;
                    cf_transition(&disp, 1);
                }
                break;
                
            case 1:
                inject_dead_code(3);
                if (opaque_complex(dummy, result)) {
                    cf_transition(&disp, 2);
                }
                break;
                
            case 2:
                if (opaque_true(dummy)) {
                    return result; // Exit point 1
                }
                cf_transition(&disp, 3);
                break;
                
            case 3:
                fake_operation(result, dummy, current);
                if (opaque_true(dummy)) {
                    return result; // Exit point 2
                }
                break;
                
            default:
                if (opaque_true(dummy)) {
                    return result; // Exit point 3
                }
                cf_transition(&disp, 0);
                break;
        }
        
        // Another exit point
        if (opaque_complex(current, 2)) {
            return result; // Exit point 4
        }
    }
    
    return result; // Unreachable but keeps compiler happy
}

// ============================================================================
// LOGGING CONTROL
// ============================================================================

#ifdef NDEBUG
    #define OBF_LOG(...)
    #define OBF_DEBUG(...)
    #define OBF_INFO(...)
    #define OBF_WARNING(...)
    #define OBF_WARN(...)
    #define OBF_ERROR(...)
#else
    #define OBF_LOG(...) fprintf(stderr, __VA_ARGS__)
    #define OBF_DEBUG(...) fprintf(stderr, "[DEBUG] " __VA_ARGS__)
    #define OBF_INFO(...) fprintf(stderr, "[INFO] " __VA_ARGS__)
    #define OBF_WARNING(...) fprintf(stderr, "[WARNING] " __VA_ARGS__)
    #define OBF_WARN(...) fprintf(stderr, "[WARNING] " __VA_ARGS__)
    #define OBF_ERROR(...) fprintf(stderr, "[ERROR] " __VA_ARGS__)
#endif

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * @brief Initialize obfuscation system
 */
static inline void obf_init(void) {
    srand((unsigned int)time(NULL));
    
    // Warm-up opaque predicates
    volatile int dummy = rand();
    (void)opaque_true(dummy);
    (void)opaque_false(dummy);
    (void)opaque_complex(dummy, dummy + 1);
}

#ifdef __cplusplus
}
#endif

#endif // CODE_OBFUSCATION_H
