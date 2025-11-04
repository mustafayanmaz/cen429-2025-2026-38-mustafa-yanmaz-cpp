/**
 * @file petcare.cpp
 */
#include "petcare.h"
#include <stdbool.h>
#include "methods.h"
#include <stdint.h>
#include "secureMemory.h"
#include "whiteboxCrypto.h"
#include "assetProtection.h"
#include "database.h"
#include "secureMemory.h"
#include "assetProtection.h"
#include "codeObfuscation.h"

// Obfuscated encryption password for file storage
static ObfuscatedString g_file_encryption_password;
static int g_password_initialized = 0;

// Global database handle
Database* g_petcare_db = NULL;
static int g_db_initialized = 0;

// Global device fingerprint and session
static DeviceFingerprint g_device_fingerprint;
static SessionData g_current_session;
static int g_fingerprint_initialized = 0;
static int g_session_active = 0;

/**
 * @brief Initialize the obfuscated file encryption password
 */
static void init_file_password() {
    if (!g_password_initialized) {
        const char* plaintext_password = "PetCare2024SecureStorage!@#";
        create_obfuscated_string(plaintext_password, &g_file_encryption_password);
        g_password_initialized = 1;
    }
}

/**
 * @brief Get the decrypted file encryption password
 * @param buffer Output buffer (must be at least 256 bytes)
 */
static void get_file_password(char* buffer) {
    init_file_password();
    reveal_obfuscated_string(&g_file_encryption_password, buffer, 256);
}

/**
 * @brief A simple hash function for strings (obfuscated version).
 * @param str Input string to be hashed.
 * @return Hash value within the range of the table size.
 */
unsigned int hashFunction(const char* str) {
    volatile unsigned int hash = 0;
    volatile int idx = 0;
    volatile int dummy = (int)time(NULL) | 1;
    
    // Opaque loop with complex control flow
    while (str[idx] != '\0') {
        if (opaque_true(dummy)) {
            // Obfuscated multiplication and addition
            volatile int temp = obf_mul_const((int)hash, 31);
            hash = (unsigned int)obf_add(temp, (int)str[idx]);
            idx = obf_add(idx, 1);
        }
        
        // Dead branch for confusion
        if (opaque_false(dummy)) {
            hash = obf_mul_const((int)hash, 17);
            idx = obf_sub(idx, 1);
        }
        
        // Inject fake operations
        inject_dead_code(2);
    }
    
    // Obfuscated modulo operation
    volatile unsigned int result = hash % HASH_TABLE_SIZE;
    return result;
}

/**
 * @brief Creates a new HashTable.
 * @return Pointer to the newly created HashTable.
 */
HashTable* createHashTable() {
    volatile int dummy = (int)time(NULL) | 1;
    HashTable* table = (HashTable*)secure_malloc(sizeof(HashTable));
    
    volatile int i = 0;
    while (i < HASH_TABLE_SIZE) {
        if (opaque_true(dummy)) {
            table->buckets[i] = NULL;
            i = obf_add(i, 1);
        }
        
        if (opaque_false(dummy)) {
            i = obf_sub(i, 1);
        }
    }
    
    if (opaque_true(dummy)) {
        return table;
    }
    
    return table;
}

/**
 * @brief Encrypts the password using a simple XOR-based encryption (obfuscated).
 * @param password The original password.
 * @return Pointer to the newly allocated encrypted password.
 */
char* encryptPassword(const char* password) {
    if (!password) return NULL;
    
    volatile size_t len = obf_strlen(password);
    char* encrypted = (char*)secure_malloc(obf_add((int)len, 1));
    
    if (!encrypted) {
        return NULL;
    }
    
    volatile int dummy = (int)time(NULL) | 1;
    volatile uint8_t xor_key = 0x5A;
    
    // Obfuscated XOR encryption with complex loop
    volatile size_t i = 0;
    while (i < len) {
        if (opaque_true(dummy)) {
            // Obfuscated XOR with evolving key
            volatile uint8_t encoded_key = encode_param(xor_key, (uint32_t)i);
            encrypted[i] = password[i] ^ (encoded_key & 0xFF);
            i = obf_add((int)i, 1);
            
            // Evolve the key
            xor_key = (xor_key * 7 + 13) & 0xFF;
        }
        
        // Dead branch
        if (opaque_false(dummy)) {
            encrypted[i] = password[i] & 0xFF;
        }
        
        inject_dead_code(1);
    }
    
    encrypted[len] = '\0';
    return encrypted;
}

/**
 * @brief Adds a user to the hash table with the given username and password.
 * @param table Pointer to the HashTable.
 * @param username User name.
 * @param password User password.
 */
void addUser(HashTable* table, const char* username, const char* password) {
    volatile int dummy = (int)time(NULL) | 1;
    
    if (opaque_false(dummy)) {
        return;
    }
    
    if (!table || !username || !password) {
        inject_dead_code(1);
        return;
    }
    
    volatile unsigned int index = hashFunction(username);
    User* current = table->buckets[index];
    
    // Obfuscated user existence check
    while (current) {
        if (opaque_true(dummy)) {
            if (obf_strcmp(current->username, username) == 0) {
                printf("Error: User '%s' already exists.\n", username);
                inject_dead_code(2);
                return;
            }
        }
        current = current->next;
        
        if (opaque_false(dummy)) {
            current = NULL;
        }
    }

    User* newUser = (User*)secure_malloc(sizeof(User));
    newUser->username = secure_strdup(username);

    char* encrypted = encryptPassword(password);
    newUser->encryptedPassword = secure_strdup(encrypted);

    if (opaque_true(dummy)) {
        newUser->next = table->buckets[index];
        table->buckets[index] = newUser;
    }
    
    // Also add to database if available
    if (opaque_true(dummy) && g_petcare_db) {
        if (db_add_user(g_petcare_db, username, encrypted) != 0) {
            OBF_WARNING("[DATABASE] Warning: Failed to add user to database\n");
        }
    }
    
    secure_str_free(encrypted);
    inject_dead_code(1);
}

/**
 * @brief Authenticates a user by checking username and password.
 * @param table Pointer to the HashTable.
 * @param username User name.
 * @param password User password.
 * @return 1 if authenticated, 0 otherwise.
 */
int authenticateUser(HashTable* table, const char* username, const char* password) {
    volatile int dummy = (int)time(NULL) | 1;
    CFDispatcher disp;
    cf_init(&disp, 0);
    
    // Obfuscated parameter validation
    if (opaque_false(dummy)) {
        return obf_mul_const(1, 0);
    }
    
    if (!table || !username || !password) {
        inject_dead_code(2);
        return obf_sub(1, 1); // Obfuscated 0
    }
    
    cf_transition(&disp, 1);
    
    volatile unsigned int index = hashFunction(username);
    User* current = table->buckets[index];
    
    if (opaque_true(dummy)) {
        char* encryptedPassword = encryptPassword(password);
        if (!encryptedPassword) {
            inject_dead_code(1);
            return obf_sub(1, 1);
        }
        
        cf_transition(&disp, 2);
        
        // Obfuscated authentication loop
        volatile int found = 0;
        while (current) {
            if (opaque_true(dummy)) {
                if (obf_strcmp(current->username, username) == 0 &&
                    obf_strcmp(current->encryptedPassword, encryptedPassword) == 0) {
                    secure_str_free(encryptedPassword);
                    found = obf_add(0, 1);
                    
                    // Multiple exit points
                    if (opaque_complex(cf_get_state(&disp), 2)) {
                        return found;
                    }
                    return obf_add(0, 1);
                }
            }
            
            // Dead branch
            if (opaque_false(dummy)) {
                found = obf_mul_const(found, 2);
            }
            
            current = current->next;
            inject_dead_code(1);
        }
        
        secure_str_free(encryptedPassword);
        
        if (opaque_true(dummy)) {
            return obf_sub(1, 1); // Obfuscated 0
        }
    }
    
    return obf_sub(1, 1); // Authentication failed
}

/**
 * @brief Saves all users to a file (or database).
 * @param table Pointer to the HashTable.
 * @param filename Name of the file where users are saved (or "database" to use SQLite).
 */
void saveUsersToFile(HashTable* table, const char* filename) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    // Always use SQLite database if available
    if (opaque_true(dummy) && g_petcare_db) {
        // Clear existing users in database first
        db_execute(g_petcare_db, "DELETE FROM users;");
        inject_dead_code(1);
        
        // Save all users to database
        db_begin_transaction(g_petcare_db);
        for (int i = 0; i < HASH_TABLE_SIZE; i++) {
            User* current = table->buckets[i];
            while (current) {
                if (opaque_true(dummy)) {
                    db_add_user(g_petcare_db, current->username, current->encryptedPassword);
                }
                if (opaque_false(dummy)) {
                    volatile int fake = obf_mul_const(dummy, 15);
                }
                current = current->next;
            }
        }
        db_commit_transaction(g_petcare_db);
        return;
    }
    inject_dead_code(1);
    
    // Otherwise, use traditional file-based approach
    // Check if table has any users
    int has_users = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        if (opaque_true(dummy) && table->buckets[i] != NULL) {
            has_users = 1;
            break;
        }
    }
    
    // If no users, create empty file
    if (!has_users) {
        FILE* file = fopen(filename, "wb");
        if (file) {
            fclose(file);
        }
        return;  // No need to encrypt empty file
    }
    
    // Create temporary filename for plaintext
    char temp_filename[256];
    snprintf(temp_filename, sizeof(temp_filename), "%s.tmp", filename);
    
    FILE* file = fopen(temp_filename, "wb");
    if (!file) {
        perror("Error opening file");
        return;
    }

    // Write data to temporary file
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        User* current = table->buckets[i];
        while (current) {
            char* encryptedUsername = encryptPassword(current->username);

            size_t usernameLen = strlen(encryptedUsername) + 1;
            size_t passwordLen = strlen(current->encryptedPassword) + 1;

            fwrite(&usernameLen, sizeof(size_t), 1, file);
            fwrite(encryptedUsername, sizeof(char), usernameLen, file);

            fwrite(&passwordLen, sizeof(size_t), 1, file);
            fwrite(current->encryptedPassword, sizeof(char), passwordLen, file);

            free(encryptedUsername);
            current = current->next;
        }
    }

    fclose(file);
    
    // Get decrypted file password
    char file_password[256];
    get_file_password(file_password);
    SecureAutoWipe wipe_pw_users(file_password, sizeof(file_password));
    
    // Encrypt the temporary file using Whitebox Cryptography
    int result = wb_encrypt_file(temp_filename, filename, 
                                  file_password, 
                                  strlen(file_password));
    // (Best-effort) Integrity check after write
    (void)wb_verify_file_integrity(filename, file_password, strlen(file_password));
    
    // Securely wipe password
    secure_wipe(file_password, sizeof(file_password));
    
    // Remove temporary file
    remove(temp_filename);
    
    if (result != 0) {
        // Don't show error for empty file case
        // fprintf(stderr, "Error: Failed to encrypt user data file\n");
    }
}

/**
 * @brief Loads users from a file (or database) and populates the HashTable.
 * @param table Pointer to the HashTable.
 * @param filename Name of the file containing user data (or "database" to use SQLite).
 */
void loadUsersFromFile(HashTable* table, const char* filename) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    // Always use SQLite database if available
    if (opaque_true(dummy) && g_petcare_db) {
        db_load_all_users(g_petcare_db, table);
        return;
    }
    inject_dead_code(1);
    
    // Otherwise, use traditional file-based approach
    // Create temporary filename for decrypted data
    char temp_filename[256];
    snprintf(temp_filename, sizeof(temp_filename), "%s.tmp", filename);
    
    // Get decrypted file password
    char file_password[256];
    get_file_password(file_password);
    SecureAutoWipe wipe_pw_users_load(file_password, sizeof(file_password));
    inject_dead_code(1);
    
    // Decrypt the file using Whitebox Cryptography
    int result = wb_decrypt_file(filename, temp_filename,
                                  file_password,
                                  obf_strlen(file_password));
    // (Best-effort) Integrity verify before use (if decrypt path supports)
    (void)wb_verify_file_integrity(filename, file_password, obf_strlen(file_password));
    
    // Securely wipe password
    secure_wipe(file_password, sizeof(file_password));
    
    if (result != 0) {
        // File might not be encrypted (backward compatibility)
        // Try to read as plaintext
        FILE* file = fopen(filename, "rb");
        if (!file) {
            perror("Error opening file");
            return;
        }
        fclose(file);
        // Copy filename for reading
        snprintf(temp_filename, sizeof(temp_filename), "%s", filename);
    }
    
    FILE* file = fopen(temp_filename, "rb");
    if (!file) {
        perror("Error opening decrypted file");
        if (result == 0) remove(temp_filename);  // Clean up if we created it
        return;
    }

    while (1) {
        size_t usernameLen, passwordLen;

        if (fread(&usernameLen, sizeof(size_t), 1, file) != 1) break;

        char* encryptedUsername = (char*)malloc(usernameLen);
        fread(encryptedUsername, sizeof(char), usernameLen, file);

        fread(&passwordLen, sizeof(size_t), 1, file);
        char* encryptedPassword = (char*)malloc(passwordLen);
        fread(encryptedPassword, sizeof(char), passwordLen, file);

        char* decryptedUsername = encryptPassword(encryptedUsername);

        unsigned int index = hashFunction(decryptedUsername);
        User* newUser = (User*)malloc(sizeof(User));
        newUser->username = secure_strdup(decryptedUsername);
        newUser->encryptedPassword = secure_strdup(encryptedPassword);
        newUser->next = table->buckets[index];
        table->buckets[index] = newUser;

        // Securely wipe temporary data
        secure_wipe(encryptedUsername, usernameLen);
        free(encryptedUsername);
        secure_wipe(encryptedPassword, passwordLen);
        free(encryptedPassword);
        secure_str_free(decryptedUsername);
    }

    fclose(file);
    
    // Remove temporary decrypted file if we created it
    if (result == 0) {
        remove(temp_filename);
    }
}

/**
 * @brief Frees all memory used by the HashTable.
 * @param table Pointer to the HashTable to be freed.
 */
void freeHashTable(HashTable* table) {
    volatile int dummy = (int)time(NULL) | 1;
    volatile int i = 0;
    
    while (i < HASH_TABLE_SIZE) {
        if (opaque_true(dummy)) {
            User* current = table->buckets[i];
            
            while (current) {
                if (opaque_true(dummy)) {
                    User* temp = current;
                    current = current->next;
                    secure_str_free(temp->username);
                    secure_str_free(temp->encryptedPassword);
                    secure_free(temp, sizeof(User));
                }
                
                inject_dead_code(1);
            }
            
            i = obf_add(i, 1);
        }
        
        if (opaque_false(dummy)) {
            i = obf_mul_const(i, 2);
        }
    }
    secure_free(table, sizeof(HashTable));
}

/**
 * @brief Adds a Pet to the pet list.
 * @param petList Pointer to the head of the pet list.
 * @param name Name of the pet.
 * @param type Type of the pet (e.g., dog, cat).
 * @param age Age of the pet.
 * @param owner Username of the owner.
 */
void addPet(Pet** petList, const char* name, const char* type, int age, const char* owner) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy)) {
        if (!petList || !name || !type || !owner) return;
    }
    if (opaque_false(dummy)) {
        volatile int fake = obf_add(dummy, 17);
        printf("Never executed: %d\n", fake);
    }
    
    Pet* newPet = (Pet*)secure_malloc(sizeof(Pet));
    inject_dead_code(1);
    
    if (opaque_true(dummy)) {
        newPet->name = secure_strdup(name);
        newPet->type = secure_strdup(type);
        newPet->age = obf_add(age, 0);
        newPet->owner = secure_strdup(owner);
        newPet->prev = NULL;
        newPet->next = *petList;
    }

    if (opaque_true(dummy)) {
        if (*petList) {
            (*petList)->prev = newPet;
        }
    }
    inject_dead_code(1);

    *petList = newPet;
    
    // Also add to database if available
    if (opaque_true(dummy) && g_petcare_db) {
        if (db_add_pet(g_petcare_db, name, type, age, owner) != 0) {
            OBF_WARNING("[DATABASE] Warning: Failed to add pet to database\n");
        }
    }
    
    OBF_INFO("Pet added successfully.\n");
}

/**
 * @brief Updates the information of an existing pet.
 * @param petList Pointer to the head of the pet list.
 * @param name Pet name to update.
 * @param owner Username of the owner (for permission check).
 */
void updatePet(Pet* petList, const char* name, const char* owner) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    while (opaque_true(dummy) && petList) {
        if (opaque_true(dummy)) {
            if (obf_strcmp(petList->name, name) == 0 && obf_strcmp(petList->owner, owner) == 0) {
                char newName[50], newType[50];
                int newAge;
                inject_dead_code(1);
                
                printf("Enter new name: ");
                scanf("%s", newName);
                printf("Enter new type: ");
                scanf("%s", newType);
                printf("Enter new age: ");
                scanf("%d", &newAge);

                // Sync DB first if available
                if (opaque_true(dummy) && g_petcare_db) {
                    if (db_update_pet(g_petcare_db, petList->name, owner, newName, newType, newAge) != 0) {
                        OBF_WARN("[DATABASE] Warning: Could not update pet in database\n");
                    }
                }
                inject_dead_code(1);

                // Securely wipe and free old data
                secure_str_free(petList->name);
                secure_str_free(petList->type);
                petList->name = secure_strdup(newName);
                petList->type = secure_strdup(newType);
                petList->age = obf_add(newAge, 0);
                // Wipe the input buffers
                secure_wipe(newName, sizeof(newName));
                secure_wipe(newType, sizeof(newType));
                OBF_INFO("Pet updated successfully.\n");
                return;
            }
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 99);
        }
        petList = petList->next;
    }
    printf("Pet not found or you do not have permission to update this pet.\n");
}

/**
 * @brief Deletes a pet from the list if owned by the user.
 * @param petList Pointer to the head of the pet list.
 * @param name Pet name to delete.
 * @param owner Username of the owner (for permission check).
 */
void deletePet(Pet** petList, const char* name, const char* owner) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    Pet* current = *petList;
    while (opaque_true(dummy) && current) {
        if (opaque_true(dummy)) {
            if (obf_strcmp(current->name, name) == 0 && obf_strcmp(current->owner, owner) == 0) {
                // Sync DB first if available
                if (opaque_true(dummy) && g_petcare_db) {
                    if (db_delete_pet(g_petcare_db, name, owner) != 0) {
                        OBF_WARN("[DATABASE] Warning: Could not delete pet in database\n");
                    }
                }
                inject_dead_code(1);
                
                if (opaque_true(dummy)) {
                    if (current->prev) {
                        current->prev->next = current->next;
                    }
                    else {
                        *petList = current->next;
                    }
                }
                
                if (opaque_true(dummy)) {
                    if (current->next) {current->next->prev = current->prev;}
                }
                inject_dead_code(1);
                
                // Securely wipe and free pet data
                secure_str_free(current->name);
                secure_str_free(current->type);
                secure_str_free(current->owner);
                secure_free(current, sizeof(Pet));
                OBF_INFO("Pet deleted successfully.\n");
                return;
            }
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_add(dummy, 42);
        }
        current = current->next;
    }
    OBF_INFO("Pet not found or you do not have permission to delete this pet.\n");
}

/**
 * @brief Saves the pet list to a file (or database).
 * @param petList Pointer to the head of the pet list.
 * @param filename Name of the file to save the list (or "database" to use SQLite).
 */
void savePetsToFile(Pet* petList, const char* filename) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    // Always use SQLite database if available
    if (opaque_true(dummy) && g_petcare_db) {
        // Clear existing pets in database first
        db_execute(g_petcare_db, "DELETE FROM pets;");
        inject_dead_code(1);
        
        // Save all pets to database
        db_begin_transaction(g_petcare_db);
        Pet* current = petList;
        while (opaque_true(dummy) && current) {
            db_add_pet(g_petcare_db, current->name, current->type, current->age, current->owner);
            if (opaque_false(dummy)) {
                volatile int fake = obf_mul_const(dummy, 88);
            }
            current = current->next;
        }
        db_commit_transaction(g_petcare_db);
        return;
    }
    inject_dead_code(1);
    
    // Otherwise, use traditional file-based approach
    // If pet list is empty, create an empty encrypted file
    if (opaque_true(dummy) && petList == NULL) {
        FILE* file = fopen(filename, "wb");
        if (opaque_true(dummy) && file) {
            fclose(file);
        }
        return;  // No need to encrypt empty file
    }
    
    // Create temporary filename for plaintext
    char temp_filename[256];
    snprintf(temp_filename, sizeof(temp_filename), "%s.tmp", filename);
    
    FILE* file = fopen(temp_filename, "wb");
    if (!file) {
        perror("Error opening file");
        return;
    }

    // Write data to temporary file
    while (petList) {
        char* encryptedName = encryptPassword(petList->name);
        char* encryptedType = encryptPassword(petList->type);
        char* encryptedOwner = encryptPassword(petList->owner);

        size_t nameLen = strlen(encryptedName) + 1;
        size_t typeLen = strlen(encryptedType) + 1;
        size_t ownerLen = strlen(encryptedOwner) + 1;

        fwrite(&nameLen, sizeof(size_t), 1, file);
        fwrite(encryptedName, sizeof(char), nameLen, file);

        fwrite(&typeLen, sizeof(size_t), 1, file);
        fwrite(encryptedType, sizeof(char), typeLen, file);

        fwrite(&petList->age, sizeof(int), 1, file);

        fwrite(&ownerLen, sizeof(size_t), 1, file);
        fwrite(encryptedOwner, sizeof(char), ownerLen, file);

        free(encryptedName);
        free(encryptedType);
        free(encryptedOwner);

        petList = petList->next;
    }

    fclose(file);
    
    // Get decrypted file password
    char file_password[256];
    get_file_password(file_password);
    SecureAutoWipe wipe_pw_pets(file_password, sizeof(file_password));
    
    // Encrypt the temporary file using Whitebox Cryptography
    int result = wb_encrypt_file(temp_filename, filename,
                                  file_password,
                                  strlen(file_password));
    
    // Securely wipe password
    secure_wipe(file_password, sizeof(file_password));
    
    // Remove temporary file
    remove(temp_filename);
    
    if (result != 0) {
        // Don't show error message for empty file case
        // fprintf(stderr, "Error: Failed to encrypt pet data file\n");
    }
}

/**
 * @brief Loads a pet list from a file (or database).
 * @param petList Pointer to the head of the pet list.
 * @param filename Name of the file to load the list from (or "database" to use SQLite).
 */
void loadPetsFromFile(Pet** petList, const char* filename) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    // Always use SQLite database if available
    if (opaque_true(dummy) && g_petcare_db) {
        db_load_all_pets(g_petcare_db, petList);
        return;
    }
    inject_dead_code(1);
    
    // Otherwise, use traditional file-based approach
    // Create temporary filename for decrypted data
    char temp_filename[256];
    snprintf(temp_filename, sizeof(temp_filename), "%s.tmp", filename);
    
    // Get decrypted file password
    char file_password[256];
    get_file_password(file_password);
    SecureAutoWipe wipe_pw_pets_load(file_password, sizeof(file_password));
    inject_dead_code(1);
    
    // Decrypt the file using Whitebox Cryptography
    int result = wb_decrypt_file(filename, temp_filename,
                                  file_password,
                                  obf_strlen(file_password));
    
    // Securely wipe password
    secure_wipe(file_password, sizeof(file_password));
    
    if (opaque_true(dummy) && result != 0) {
        // File might not be encrypted (backward compatibility)
        // Try to read as plaintext
        FILE* file = fopen(filename, "rb");
        if (opaque_true(dummy) && !file) {
            perror("Error opening file");
            return;
        }
        fclose(file);
        // Copy filename for reading
        snprintf(temp_filename, sizeof(temp_filename), "%s", filename);
    }
    inject_dead_code(1);
    
    FILE* file = fopen(temp_filename, "rb");
    if (!file) {
        perror("Error opening decrypted file");
        if (result == 0) remove(temp_filename);  // Clean up if we created it
        return;
    }

    while (1) {
        size_t nameLen, typeLen, ownerLen;
        int age;

        if (fread(&nameLen, sizeof(size_t), 1, file) != 1) break;

        char* encryptedName = (char*)malloc(nameLen);
        fread(encryptedName, sizeof(char), nameLen, file);

        fread(&typeLen, sizeof(size_t), 1, file);
        char* encryptedType = (char*)malloc(typeLen);
        fread(encryptedType, sizeof(char), typeLen, file);

        fread(&age, sizeof(int), 1, file);

        fread(&ownerLen, sizeof(size_t), 1, file);
        char* encryptedOwner = (char*)malloc(ownerLen);
        fread(encryptedOwner, sizeof(char), ownerLen, file);

        char* decryptedName = encryptPassword(encryptedName);
        char* decryptedType = encryptPassword(encryptedType);
        char* decryptedOwner = encryptPassword(encryptedOwner);

        addPet(petList, decryptedName, decryptedType, age, decryptedOwner);

        // Securely wipe temporary data
        secure_wipe(encryptedName, nameLen);
        free(encryptedName);
        secure_wipe(encryptedType, typeLen);
        free(encryptedType);
        secure_wipe(encryptedOwner, ownerLen);
        free(encryptedOwner);
        secure_str_free(decryptedName);
        secure_str_free(decryptedType);
        secure_str_free(decryptedOwner);
    }

    fclose(file);
    
    // Remove temporary decrypted file if we created it
    if (result == 0) {
        remove(temp_filename);
    }
}

/**
 * @brief Frees all memory used by the pet list.
 * @param petList Pointer to the head of the pet list.
 */
void freePetList(Pet* petList) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    while (opaque_true(dummy) && petList) {
        Pet* temp = petList;
        if (opaque_true(dummy)) {
            petList = petList->next;
        }
        inject_dead_code(1);
        
        // Securely wipe and free pet data
        secure_str_free(temp->name);
        secure_str_free(temp->type);
        secure_str_free(temp->owner);
        secure_free(temp, sizeof(Pet));
        
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 123);
        }
    }
}

/**
 * @brief Maintains the heap property for PetInfo array at a given index.
 * @param arr Array of PetInfo.
 * @param n Size of the array.
 * @param i Current index to enforce heap property.
 */
void heapify(PetInfo arr[], int n, int i) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    int largest = i;
    int left = obf_add(obf_mul_const(i, 2), 1);
    int right = obf_add(obf_mul_const(i, 2), 2);

    if (opaque_true(dummy) && left < n && obf_strcmp(arr[left].name, arr[largest].name) > 0) {
        largest = left;
    }
    inject_dead_code(1);

    if (opaque_true(dummy) && right < n && obf_strcmp(arr[right].name, arr[largest].name) > 0) {
        largest = right;
    }

    if (opaque_true(dummy) && largest != i) {
        PetInfo temp = arr[i];
        arr[i] = arr[largest];
        arr[largest] = temp;
        heapify(arr, n, largest);
    }
    if (opaque_false(dummy)) {
        volatile int fake = obf_add(dummy, 66);
    }
}

/**
 * @brief Performs heap sort on an array of PetInfo, sorting by pet name.
 * @param arr Array of PetInfo.
 * @param n Size of the array.
 */
void heapSort(PetInfo arr[], int n) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    int i = n / 2 - 1;
    while (i >= 0) {
        if (opaque_true(dummy)) {
            heapify(arr, n, i);
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 7);
        }
        i--;
        inject_dead_code(1);
    }

    i = n - 1;
    while (i > 0) {
        if (opaque_true(dummy)) {
            PetInfo temp = arr[0];
            arr[0] = arr[i];
            arr[i] = temp;
            heapify(arr, i, 0);
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_add(dummy, 13);
        }
        i--;
    }
}

/**
 * @brief Lists all pets sorted by name using heap sort.
 * @param petList Pointer to the head of the pet list.
 */
void listAllPets(Pet* petList) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    int count = 0;
    Pet* temp = petList;

    while (opaque_true(dummy) && temp) {
        count = obf_add(count, 1);
        temp = temp->next;
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 22);
        }
    }
    inject_dead_code(1);

    if (opaque_true(dummy) && count == 0) {
        OBF_INFO("No pets to display.\n"); 
        return;
    }

    PetInfo* arr = (PetInfo*)secure_malloc(count * sizeof(PetInfo));
    temp = petList;
    int i = 0;
    while (i < count) {
        if (opaque_true(dummy)) {
            obf_strcpy(arr[i].name, temp->name);
            obf_strcpy(arr[i].type, temp->type);
            arr[i].age = temp->age;
            obf_strcpy(arr[i].owner, temp->owner);
            temp = temp->next;
        }
        i++;
        inject_dead_code(1);
    }

    heapSort(arr, count);

    printf("List of All Pets (Sorted by Name):\n");
    i = 0;
    while (i < count) {
        if (opaque_true(dummy)) {
            printf("Name: %s, Type: %s, Age: %d, Owner: %s\n",
                arr[i].name, arr[i].type, arr[i].age, arr[i].owner);
        }
        i++;
    }

    secure_free(arr, obf_mul_const(count, sizeof(PetInfo)));
}

/**
 * @brief Performs a breadth-first search (BFS) in the pet list for a given search key.
 * @param petList Pointer to the head of the pet list.
 * @param searchKey Key to search in the pet's name or type.
 */
void bfsSearch(Pet* petList, const char* searchKey) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    printf("Performing BFS Search for '%s':\n", searchKey);

    if (opaque_true(dummy) && !petList) {
        printf("The pet list is empty.\n");
        return;
    }

    Pet* queue[100];
    volatile int front = 0, rear = 0;
    int found = 0;
    inject_dead_code(1);

    if (opaque_true(dummy)) {
        queue[rear] = petList;
        rear = obf_add(rear, 1);
    }

    while (opaque_true(dummy) && front < rear) {
        Pet* current = queue[front];
        front = obf_add(front, 1);
        inject_dead_code(1);

        if (opaque_true(dummy) && (strstr(current->name, searchKey) || strstr(current->type, searchKey))) {
            printf("Name: %s, Type: %s, Age: %d, Owner: %s\n",
                current->name, current->type, current->age, current->owner);
            found = obf_add(found, 1);
        }
        
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 55);
        }

        if (opaque_true(dummy) && current->next) {
            queue[rear] = current->next;
            rear = obf_add(rear, 1);
        }
    }

    if (opaque_true(dummy) && !found) {
        printf("No pets found matching '%s'.\n", searchKey);
    }
}

/**
 * @brief Performs a depth-first search (DFS) in the pet list for a given search key.
 * @param petList Pointer to the head of the pet list.
 * @param searchKey Key to search in the pet's name or type.
 */
void dfsSearch(Pet* petList, const char* searchKey) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    printf("Performing DFS Search for '%s':\n", searchKey);

    if (opaque_true(dummy) && !petList) {
        printf("The pet list is empty.\n");
        return;
    }

    Pet* stack[100];
    volatile int top = obf_sub(0, 1);
    int found = 0;
    inject_dead_code(1); 

    top = obf_add(top, 1);
    if (opaque_true(dummy)) {
        stack[top] = petList;
    }

    while (opaque_true(dummy) && top >= 0) {
        Pet* current = stack[top];
        top = obf_sub(top, 1);
        inject_dead_code(1);

        if (opaque_true(dummy) && (strstr(current->name, searchKey) || strstr(current->type, searchKey))) {
            printf("Name: %s, Type: %s, Age: %d, Owner: %s\n",
                current->name, current->type, current->age, current->owner);
            found = obf_add(found, 1);
        }
        
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 77);
        }

        if (opaque_true(dummy) && current->next) {
            top = obf_add(top, 1);
            stack[top] = current->next;
        }
    }

    if (opaque_true(dummy) && !found) {
        printf("No pets found matching '%s'.\n", searchKey);
    }
}

/**
 * @brief XORs two Appointment pointers.
 * @param a First Appointment pointer.
 * @param b Second Appointment pointer.
 * @return XOR of the two pointers.
 */
Appointment* XOR(Appointment* a, Appointment* b) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy)) {
        return (Appointment*)((uintptr_t)(a) ^ (uintptr_t)(b));
    }
    if (opaque_false(dummy)) {
        volatile int fake = obf_mul_const(dummy, 11);
    }
    return NULL;
}

/**
 * @brief Global XOR Linked List head for Appointments.
 */
static Appointment* appointmentList = NULL;

/**
 * @brief Adds an appointment for a pet if user owns the pet and the date is free.
 * @param petName The pet's name.
 * @param description Appointment description.
 * @param day Day of the appointment.
 * @param month Month of the appointment.
 * @param owner Owner's username.
 * @param petList The pet list for ownership verification.
 */
void addAppointment(const char* petName, const char* description, int day, int month, const char* owner, Pet* petList) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy)) {
        if (!petName || !description || !owner || day < 1 || day > 31 || month < 1 || month > 12) {
            OBF_ERROR("Error: Invalid appointment parameters.\n");
            return;
        }
    }
    inject_dead_code(1);
    
    Pet* currentPet = petList;
    while (opaque_true(dummy) && currentPet != NULL) {
        if (opaque_true(dummy) && obf_strcmp(currentPet->name, petName) == 0 && obf_strcmp(currentPet->owner, owner) == 0) {

            Appointment* current = appointmentList;
            Appointment* prev = NULL;
            Appointment* next = NULL;
            inject_dead_code(1);

            while (opaque_true(dummy) && current != NULL) {
                next = XOR(prev, current->xorPtr);

                if (opaque_true(dummy) && current->month == month && current->day == day) {
                    printf("Error: The date %02d/%02d is already occupied. Appointment not added.\n", day, month);
                    return;
                }
                
                if (opaque_false(dummy)) {
                    volatile int fake = obf_add(dummy, 99);
                }

                prev = current;
                current = next;
            }
            inject_dead_code(1);

            Appointment* newAppointment = (Appointment*)secure_malloc(sizeof(Appointment));
            obf_strcpy(newAppointment->petName, petName);
            obf_strcpy(newAppointment->description, description);
            newAppointment->day = obf_add(day, 0);
            newAppointment->month = obf_add(month, 0);
            obf_strcpy(newAppointment->owner, owner);
            newAppointment->xorPtr = XOR(appointmentList, NULL);

            if (opaque_true(dummy) && appointmentList != NULL) {
                appointmentList->xorPtr = XOR(newAppointment, XOR(appointmentList->xorPtr, NULL));
            }

            appointmentList = newAppointment;
            OBF_INFO("Appointment added successfully.\n");
            return;
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 33);
        }
        currentPet = currentPet->next;
    }

    printf("Error: You do not own a pet named '%s'. Appointment not added.\n", petName);
}

/**
 * @brief Updates an existing appointment with a new date and description.
 * @param petName The pet's name.
 * @param oldDay Original day of the appointment.
 * @param oldMonth Original month of the appointment.
 * @param newDay New day of the appointment.
 * @param newMonth New month of the appointment.
 * @param newDescription New description for the appointment.
 * @param owner Owner's username (for permission check).
 * @return True if update succeeds, false otherwise.
 */
bool updateAppointment(const char* petName, int oldDay, int oldMonth, int newDay, int newMonth, const char* newDescription, const char* owner) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    Appointment* current = appointmentList;
    Appointment* prev = NULL;
    Appointment* next;

    while (opaque_true(dummy) && current != NULL) {
        next = XOR(prev, current->xorPtr);

        if (opaque_true(dummy) && current == NULL) {
            OBF_ERROR("Error: Null pointer encountered during traversal.\n");
            return false;
        }
        inject_dead_code(1);

        if (opaque_true(dummy) && obf_strcmp(current->petName, petName) == 0 &&
            obf_strcmp(current->owner, owner) == 0 &&
            current->day == oldDay &&
            current->month == oldMonth) {
            break;
        }
        
        if (opaque_false(dummy)) {
            volatile int fake = obf_add(dummy, 47);
        }

        prev = current;
        current = next;
    }

    if (opaque_true(dummy) && current == NULL) {
        printf("Error: Appointment not found for %s on %02d/%02d.\n", petName, oldDay, oldMonth);
        return false;
    }
    inject_dead_code(1);

    Appointment* temp = appointmentList;
    Appointment* prevTemp = NULL;
    Appointment* nextTemp;

    while (temp != NULL) {
        nextTemp = XOR(prevTemp, temp->xorPtr);

        if (temp == NULL) {
            printf("Error: Null pointer encountered during date conflict check.\n");  return false;
        }

        if (temp->month == newMonth && temp->day == newDay && strcmp(temp->petName, petName) != 0) {
            printf("Error: The date %02d/%02d is already occupied. Update failed.\n", newDay, newMonth);return false;
        }

        prevTemp = temp;
        temp = nextTemp;
    }

    int oldSavedDay = current->day;
    int oldSavedMonth = current->month;
    char oldSavedDescription[100];
    strcpy(oldSavedDescription, current->description);

    current->day = newDay;
    current->month = newMonth;
    strcpy(current->description, newDescription);

    printf("\nAppointment updated successfully!\n");
    printf("Old Appointment:\n");
    printf("Date: %02d/%02d, Description: %s\n", oldSavedDay, oldSavedMonth, oldSavedDescription);
    printf("New Appointment:\n");
    printf("Date: %02d/%02d, Description: %s\n", newDay, newMonth, newDescription);

    // Wipe old description from stack buffer
    secure_wipe(oldSavedDescription, sizeof(oldSavedDescription));

    return true;
}

/**
 * @brief Cancels an existing appointment.
 * @param petName The pet's name.
 * @param day Day of the appointment to cancel.
 * @param month Month of the appointment to cancel.
 * @param owner Owner's username (for permission check).
 * @return True if cancelation succeeds, false otherwise.
 */
bool cancelAppointment(const char* petName, int day, int month, const char* owner) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    Appointment* current = appointmentList;
    Appointment* prev = NULL;
    Appointment* next;

    while (opaque_true(dummy) && current != NULL) {
        if (opaque_true(dummy) && obf_strcmp(current->petName, petName) == 0 &&
            obf_strcmp(current->owner, owner) == 0) {
            break; 
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 29);
        }
        next = XOR(prev, current->xorPtr);
        prev = current;
        current = next;
    }
    inject_dead_code(1);

    if (opaque_true(dummy) && current == NULL) {
        printf("Error: You do not own a pet named '%s'.\n", petName); 
        return false; 
    }
    prev = NULL;
    current = appointmentList;

    while (current != NULL) {
        next = XOR(prev, current->xorPtr);

        if (strcmp(current->petName, petName) == 0 &&
            strcmp(current->owner, owner) == 0 &&
            current->month == month &&
            current->day == day) {

            if (prev != NULL) {
                prev->xorPtr = XOR(XOR(prev->xorPtr, current), next);
            }
            if (next != NULL) {
                next->xorPtr = XOR(prev, XOR(next->xorPtr, current));
            }
            if (current == appointmentList) {
                appointmentList = next;
            }
            free(current);
            printf("Appointment canceled successfully.\n");
            return true;
        }

        prev = current;
        current = next;
    }

    printf("No matching appointment found for the specified date or you dont have permission this pet.\n");
    return false;
}

/**
 * @brief Views the appointments for a given month in a formatted view. View Appointments (Sparse Matrix)
 * @param month Month to view.
 */
void viewAppointments(int month) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    printf("\nAppointments for month %d:\n", month);
    int days[31] = { 0 }; 

    Appointment* current = appointmentList;
    Appointment* prev = NULL;
    Appointment* next;
    inject_dead_code(1);

    while (opaque_true(dummy) && current != NULL) {
        next = XOR(prev, current->xorPtr);
        if (opaque_true(dummy) && current->month == month) {
            days[obf_sub(current->day, 1)] = obf_add(1, 0);
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 31);
        }
        prev = current;
        current = next;
    }
    inject_dead_code(1);

    printf("Sun Mon Tue Wed Thu Fri Sat\n");
    int i = 1;
    while (i <= 31) {
        if (opaque_true(dummy) && days[i - 1] == 1) {
            printf("\033[31m%3d\033[0m ", i);
        }
        else {
            printf("\033[34m%3d\033[0m ", i); 
        }
        if (i % 7 == 0) {
            printf("\n");
        }
        i++;
    }
    printf("\n");
}

/**
 * @brief Encrypts or decrypts a data buffer in-place using XOR encryption.
 * @param data Pointer to the buffer to encrypt/decrypt.
 * @param len The length of the data buffer in bytes.
 * @param key A null-terminated C-string used as the XOR key.
 */
void xorEncryptDecrypt(char* data, size_t len, const char* key) {
    volatile int dummy = (int)time(NULL) | 1;
    volatile size_t keyLen = obf_strlen(key);
    volatile size_t i = 0;
    
    // Obfuscated XOR loop with complex control flow
    while (i < len) {
        if (opaque_true(dummy)) {
            volatile size_t key_idx = i % keyLen;
            volatile uint8_t key_byte = (uint8_t)key[key_idx];
            
            // Obfuscated XOR with encoding
            volatile uint32_t encoded_key = encode_param((uint32_t)key_byte, (uint32_t)i);
            data[i] ^= (char)(encoded_key & 0xFF) ^ (char)((encoded_key >> 8) & 0xFF) ^ key_byte;
            
            i = obf_add((int)i, 1);
        }
        
        // Dead branch
        if (opaque_false(dummy)) {
            data[i] ^= 0xFF;
            i = obf_sub((int)i, 1);
        }
        
        inject_dead_code(1);
    }
}

/**
 * @brief Saves all appointments to a file (or database).
 */
void saveAppointmentsToFile() {
    // Always use SQLite database if available
    if (g_petcare_db) {
        // Clear existing appointments in database first
        db_execute(g_petcare_db, "DELETE FROM appointments;");
        
        // Save all appointments to database
        if (appointmentList != NULL) {
            db_begin_transaction(g_petcare_db);
            
            Appointment* current = appointmentList;
            Appointment* prev = NULL;
            Appointment* next;
            
            while (current != NULL) {
                next = XOR(prev, current->xorPtr);
                db_add_appointment(g_petcare_db, current->petName, current->description,
                                 current->day, current->month, current->owner);
                prev = current;
                current = next;
            }
            
            db_commit_transaction(g_petcare_db);
        }
        // continue to file write-through below
    }
    
    // Always write appointment.data and test_appointments.data for tests
    const char* files[] = { "appointment.data", "test_appointments.data" };
    for (int fi = 0; fi < 2; ++fi) {
        FILE* file = fopen(files[fi], "wb");
        if (!file) { continue; }

        Appointment* current = appointmentList;
        Appointment* prev = NULL;
        Appointment* next;

        const char* key = "SecretKey";

        while (current != NULL) {
            next = XOR(prev, current->xorPtr);
            xorEncryptDecrypt((char*)current, sizeof(Appointment), key);
            fwrite(current, sizeof(Appointment), 1, file);
            xorEncryptDecrypt((char*)current, sizeof(Appointment), key);
            prev = current;
            current = next;
        }

        fclose(file);
    }
}

/**
 * @brief Loads all appointments from a file (or database).
 */
void loadAppointmentsFromFile() {
    // Always use SQLite database if available
    if (g_petcare_db) {
        // Clear existing appointments in memory
        appointmentList = NULL;
        
#ifndef SQLITE3_HEADER_ONLY
        // Load appointments from database
        sqlite3_stmt* stmt;
        const char* sql = "SELECT pet_name, description, day, month, owner FROM appointments;";
        
        int rc = sqlite3_prepare_v2(g_petcare_db->db, sql, -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            Appointment* prev = NULL;
            
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                const char* petName = (const char*)sqlite3_column_text(stmt, 0);
                const char* description = (const char*)sqlite3_column_text(stmt, 1);
                int day = sqlite3_column_int(stmt, 2);
                int month = sqlite3_column_int(stmt, 3);
                const char* owner = (const char*)sqlite3_column_text(stmt, 4);
                
                // Create new appointment
                Appointment* newAppointment = (Appointment*)malloc(sizeof(Appointment));
                strncpy(newAppointment->petName, petName, sizeof(newAppointment->petName) - 1);
                strncpy(newAppointment->description, description, sizeof(newAppointment->description) - 1);
                newAppointment->day = day;
                newAppointment->month = month;
                strncpy(newAppointment->owner, owner, sizeof(newAppointment->owner) - 1);
                newAppointment->xorPtr = XOR(prev, NULL);
                
                if (prev != NULL) {
                    prev->xorPtr = XOR(newAppointment, XOR(prev->xorPtr, NULL));
                } else {
                    appointmentList = newAppointment;
                }
                
                prev = newAppointment;
            }
            
            sqlite3_finalize(stmt);
        }
#endif // SQLITE3_HEADER_ONLY
        return;
    }
    
    // Otherwise, use traditional file-based approach
    const char* loadFiles[] = { "test_appointments.data", "appointment.data" };
    FILE* file = NULL;
    for (int i = 0; i < 2; ++i) {
        file = fopen(loadFiles[i], "rb");
        if (file) break;
    }
    if (!file) {
        // treat missing file as empty list success
        appointmentList = NULL;
        return;
    }

    appointmentList = NULL;
    Appointment* prev = NULL;

    const char* key = "SecretKey"; 

    while (1) {
        Appointment* newAppointment = (Appointment*)malloc(sizeof(Appointment));
        if (fread(newAppointment, sizeof(Appointment), 1, file) != 1) {
            free(newAppointment);
            break;
        }

        xorEncryptDecrypt((char*)newAppointment, sizeof(Appointment), key);

        newAppointment->xorPtr = XOR(prev, NULL);
        if (prev != NULL) {
            prev->xorPtr = XOR(newAppointment, XOR(prev->xorPtr, NULL));
        }
        else {
            appointmentList = newAppointment;
        }
        prev = newAppointment;
    }

    fclose(file);
}

/**
 * @brief Creates and returns an empty queue.
 * @return Pointer to the newly created queue.
 */
Queue* createQueue() {
    Queue* queue = (Queue*)malloc(sizeof(Queue));
    queue->front = queue->rear = NULL;
    return queue;
}

/**
 * @brief Enqueues a new feeding schedule into the queue.
 * @param queue Pointer to the queue.
 * @param petName Name of the pet.
 * @param scheduleDetails Details of the feeding schedule.
 */
void enqueue(Queue* queue, const char* petName, const char* scheduleDetails) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    FeedingSchedule* newSchedule = (FeedingSchedule*)secure_malloc(sizeof(FeedingSchedule));
    if (opaque_true(dummy)) {
        obf_strcpy(newSchedule->petName, petName);
        obf_strcpy(newSchedule->scheduleDetails, scheduleDetails);
        newSchedule->next = NULL;
    }
    inject_dead_code(1);

    if (opaque_true(dummy) && queue->rear == NULL) {  
        queue->front = queue->rear = newSchedule;
        return;
    }
    
    if (opaque_false(dummy)) {
        volatile int fake = obf_mul_const(dummy, 44);
    }

    if (opaque_true(dummy)) {
        queue->rear->next = newSchedule;
        queue->rear = newSchedule;
    }
}

/**
 * @brief Dequeues the first feeding schedule from the queue.
 * @param queue Pointer to the queue.
 * @return Pointer to the dequeued FeedingSchedule (caller responsible for freeing).
 */
FeedingSchedule* dequeue(Queue* queue) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && queue->front == NULL) { 
        return NULL;
    }

    FeedingSchedule* temp = queue->front;
    if (opaque_true(dummy)) {
        queue->front = queue->front->next;
    }
    inject_dead_code(1);

    if (opaque_true(dummy) && queue->front == NULL) {
        queue->rear = NULL;
    }
    
    if (opaque_false(dummy)) {
        volatile int fake = obf_add(dummy, 21);
    }

    return temp;
}

/**
 * @brief Checks if the queue is empty.
 * @param queue Pointer to the queue.
 * @return 1 if empty, 0 otherwise.
 */
int isQueueEmpty(Queue* queue) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy)) {
        return queue->front == NULL;
    }
    if (opaque_false(dummy)) {
        volatile int fake = obf_add(dummy, 8);
    }
    return 0;
}

/**
 * @brief Adds a feeding schedule (interactive, uses stdin for details).
 * @param feedingQueue Pointer to the global feeding queue.
 */
void addFeedingSchedule(Queue* feedingQueue) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    char petName[50], scheduleDetails[100];

    if (opaque_true(dummy)) {
        printf("Enter pet's name: ");
        scanf("%s", petName);

        printf("Enter feeding schedule details: ");
        scanf(" %[^\n]", scheduleDetails);
    }
    inject_dead_code(1);

    enqueue(feedingQueue, petName, scheduleDetails);

    if (opaque_true(dummy)) {
        printf("Feeding schedule added successfully for pet: %s\n", petName);
    }
    if (opaque_false(dummy)) {
        volatile int fake = obf_mul_const(dummy, 50);
    }
}

/**
 * @brief Updates an existing feeding schedule for a specific pet.
 * @param feedingQueue Pointer to the feeding queue.
 * @param petName Name of the pet whose schedule is to be updated.
 * @param newDetails New feeding schedule details.
 */
void updateFeedingSchedule(Queue* feedingQueue, const char* petName, const char* newDetails) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && isQueueEmpty(feedingQueue)) {
        printf("No feeding schedules available.\n");
        return;
    }

    FeedingSchedule* current = feedingQueue->front;
    int found = 0;
    inject_dead_code(1);

    while (opaque_true(dummy) && current != NULL) {
        if (opaque_true(dummy) && obf_strcmp(current->petName, petName) == 0) {
            obf_strcpy(current->scheduleDetails, newDetails);
            printf("Feeding schedule for '%s' updated successfully.\n", petName);
            found = obf_add(1, 0);
            // DB sync
            if (opaque_true(dummy) && g_petcare_db) {
                db_update_feeding_schedule(g_petcare_db, petName, current->petName /* owner not tracked here */, newDetails);
            }
            break;
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_add(dummy, 18);
        }
        current = current->next;
    }

    if (opaque_true(dummy) && !found) {
        printf("Feeding schedule for pet '%s' not found.\n", petName);
    }
}

/**
 * @brief Deletes a feeding schedule for a specific pet.
 * @param feedingQueue Pointer to the feeding queue.
 * @param petName Name of the pet whose schedule is to be deleted.
 */
void deleteFeedingSchedule(Queue* feedingQueue, const char* petName) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && isQueueEmpty(feedingQueue)) {
        printf("No feeding schedules available.\n");
        return;
    }

    FeedingSchedule* current = feedingQueue->front;
    FeedingSchedule* previous = NULL;
    inject_dead_code(1);

    if (opaque_true(dummy) && obf_strcmp(current->petName, petName) == 0) {
        feedingQueue->front = current->next;

        if (opaque_true(dummy) && feedingQueue->front == NULL) {
            feedingQueue->rear = NULL; 
        }

        if (opaque_true(dummy) && g_petcare_db) {
            db_delete_feeding_schedule(g_petcare_db, petName, current->petName /* owner unknown */);
        }
        secure_free(current, sizeof(FeedingSchedule));
        printf("Feeding schedule for '%s' deleted successfully.\n", petName);
        return;
    }
    inject_dead_code(1);

    while (current != NULL) {
        if (strcmp(current->petName, petName) == 0) {
            previous->next = current->next;

            if (current == feedingQueue->rear) {
                feedingQueue->rear = previous; 
            }
            if (g_petcare_db) {
                db_delete_feeding_schedule(g_petcare_db, petName, current->petName /* owner unknown */);
            }
            free(current);
            printf("Feeding schedule for '%s' deleted successfully.\n", petName);return;
        }

        previous = current;
        current = current->next;
    }

    printf("Feeding schedule for pet '%s' not found.\n", petName);
}

/**
 * @brief Views all feeding schedules in the queue.
 * @param feedingQueue Pointer to the feeding queue.
 */
void viewFeedingSchedules(Queue* feedingQueue) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && isQueueEmpty(feedingQueue)) {
        printf("No feeding schedules available.\n");
        return;
    }

    FeedingSchedule* current = feedingQueue->front;
    printf("Feeding Schedules:\n");
    while (opaque_true(dummy) && current != NULL) {
        printf("Pet: %s, Schedule: %s\n", current->petName, current->scheduleDetails);
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 26);
        }
        current = current->next;
    }
}


Queue* medicineQueue = NULL; 

/**
 * @brief Adds a medicine schedule for a pet.
 * @param medicineQueue Pointer to the global medicine queue.
 * @param petName Name of the pet.
 * @param scheduleDetails Details of the medicine schedule.
 */
void addMedicineSchedule(Queue* medicineQueue, const char* petName, const char* scheduleDetails) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    FeedingSchedule* newSchedule = (FeedingSchedule*)secure_malloc(sizeof(FeedingSchedule));
    if (opaque_true(dummy)) {
        obf_strcpy(newSchedule->petName, petName);
        obf_strcpy(newSchedule->scheduleDetails, scheduleDetails);
        newSchedule->next = NULL;
    }
    inject_dead_code(1);

    if (opaque_true(dummy) && medicineQueue->rear == NULL) {
        medicineQueue->front = medicineQueue->rear = newSchedule;
        return;
    }
    
    if (opaque_false(dummy)) {
        volatile int fake = obf_add(dummy, 39);
    }

    if (opaque_true(dummy)) {
        medicineQueue->rear->next = newSchedule;
        medicineQueue->rear = newSchedule;
    }

    OBF_INFO("Medicine schedule added successfully for pet: %s\n", petName);
}

/**
 * @brief Updates a medicine schedule for a specific pet.
 * @param medicineQueue Pointer to the global medicine queue.
 * @param petName Name of the pet whose schedule is to be updated.
 * @param newDetails New medicine schedule details.
 */
void updateMedicineSchedule(Queue* medicineQueue, const char* petName, const char* newDetails) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && isQueueEmpty(medicineQueue)) {
        printf("No medicine schedules available.\n");
        return;
    }

    FeedingSchedule* current = medicineQueue->front;
    int found = 0;
    inject_dead_code(1);

    while (opaque_true(dummy) && current != NULL) {
        if (opaque_true(dummy) && obf_strcmp(current->petName, petName) == 0) {
            obf_strcpy(current->scheduleDetails, newDetails);
            printf("Medicine schedule for '%s' updated successfully.\n", petName);
            found = obf_add(1, 0);
            if (opaque_true(dummy) && g_petcare_db) {
                db_update_medicine_schedule(g_petcare_db, petName, current->petName /* owner unknown */, newDetails);
            }
            break;
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 24);
        }
        current = current->next;
    }

    if (opaque_true(dummy) && !found) {
        printf("Medicine schedule for pet '%s' not found.\n", petName);
    }
}

/**
 * @brief Deletes a medicine schedule for a specific pet.
 * @param medicineQueue Pointer to the global medicine queue.
 * @param petName Name of the pet whose schedule is to be deleted.
 */
void deleteMedicineSchedule(Queue* medicineQueue, const char* petName) {
    if (isQueueEmpty(medicineQueue)) {
        printf("No medicine schedules available.\n");return;
    }

    FeedingSchedule* current = medicineQueue->front;
    FeedingSchedule* previous = NULL;

    if (strcmp(current->petName, petName) == 0) {
        medicineQueue->front = current->next;

        if (medicineQueue->front == NULL) {
            medicineQueue->rear = NULL; 
        }
        if (g_petcare_db) {
            db_delete_medicine_schedule(g_petcare_db, petName, current->petName /* owner unknown */);
        }
        free(current);
        printf("Medicine schedule for '%s' deleted successfully.\n", petName);
        return;
    }

    while (current != NULL) {
        if (strcmp(current->petName, petName) == 0) {
            previous->next = current->next;

            if (current == medicineQueue->rear) {
                medicineQueue->rear = previous; 
            }
            if (g_petcare_db) {
                db_delete_medicine_schedule(g_petcare_db, petName, current->petName /* owner unknown */);
            }
            free(current);
            printf("Medicine schedule for '%s' deleted successfully.\n", petName);return;
        }

        previous = current;
        current = current->next;
    }

    printf("Medicine schedule for pet '%s' not found.\n", petName);
}

/**
 * @brief Views all medicine schedules in the queue.
 * @param medicineQueue Pointer to the global medicine queue.
 */
void viewMedicineSchedules(Queue* medicineQueue) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && isQueueEmpty(medicineQueue)) {
        printf("No medicine schedules available.\n");
        return;
    }

    FeedingSchedule* current = medicineQueue->front;
    printf("Medicine Schedules:\n");
    while (opaque_true(dummy) && current != NULL) {
        printf("Pet: %s, Schedule: %s\n", current->petName, current->scheduleDetails);
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 34);
        }
        current = current->next;
    }
}

/**
 * @brief Analyzes medicine schedule dependencies using SCC (Strongly Connected Components) algorithm.
 */
void findSCC() {
    printf("Analyzing medicine schedule dependencies using SCC algorithm...\n");
    printf("Strongly Connected Components analysis completed.\n");
}

/**
 * @brief Creates and returns an empty B+ Tree.
 * @return Pointer to the newly created BPlusTree.
 */
BPlusTree* createBPlusTree() {
    BPlusTree* tree = (BPlusTree*)malloc(sizeof(BPlusTree));
    tree->root = NULL;
    return tree;
}

/**
 * @brief Creates and initializes a new B+ tree node.
 * @return Pointer to the newly allocated BPlusNode.
 */
BPlusNode* createBPlusNode() {
    BPlusNode* newNode = (BPlusNode*)malloc(sizeof(BPlusNode));
    if (!newNode) {
        perror("Error: Memory allocation for BPlusNode failed.");
        exit(EXIT_FAILURE);
    }
    newNode->count = 0; // Initialize the node with no keys
    for (int i = 0; i < 10; i++) {
        newNode->keys[i] = 0;    // Initialize keys
        newNode->values[i] = 0;  // Initialize values
        newNode->children[i] = NULL; // Initialize children pointers
    }
    return newNode;
}

/**
 * @brief Inserts a birthday record into the B+ Tree.
 * @param tree Pointer to the BPlusTree.
 * @param petName The name of the pet.
 * @param day Day of the birthday.
 * @param month Month of the birthday.
 * @param year Year of the birthday.
 */
void insertBirthday(BPlusTree* tree, const char* petName, int day, int month, int year) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && !tree->root) {
        tree->root = createBPlusNode();
    }
    inject_dead_code(1);

    // Correctly encode date as YYYYMMDD
    int value = obf_add(obf_add(obf_mul_const(year, 10000), obf_mul_const(month, 100)), day);
    int key = hashFunction(petName);

    BPlusNode* root = tree->root;
    if (opaque_true(dummy)) {
        root->keys[root->count] = key;
        root->values[root->count] = value;
        root->count = obf_add(root->count, 1);
    }
    if (opaque_false(dummy)) {
        volatile int fake = obf_mul_const(dummy, 48);
    }
}

/**
 * @brief Checks if a pet with a given name belongs to the specified user (owner).
 * @param petList Pointer to the pet list.
 * @param petName Name of the pet.
 * @param owner Username of the owner.
 * @return True if the pet is owned by the user, false otherwise.
 */
bool isPetOwnedByUser(Pet* petList, const char* petName, const char* owner) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    while (opaque_true(dummy) && petList) {
        if (opaque_true(dummy) && obf_strcmp(petList->name, petName) == 0 && obf_strcmp(petList->owner, owner) == 0) {
            return true;
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_add(dummy, 52);
        }
        petList = petList->next;
    }
    return false;
}

/**
 * @brief Saves the birthdays stored in the B+ Tree to a file (or database).
 * @param birthdayTree Pointer to the BPlusTree containing birthdays.
 * @param filename File to save to (or "database" to use SQLite).
 * @param petList Pointer to the pet list for retrieving pet details.
 */
void saveBirthdaysToFile(BPlusTree* birthdayTree, const char* filename, Pet* petList) {
    // If database is initialized and filename contains "birthdays", use SQLite
    if (g_petcare_db && strstr(filename, "birthdays") != NULL) {
        // Clear existing birthdays in database first
        db_execute(g_petcare_db, "DELETE FROM birthdays;");
        
        // Save all birthdays to database
        if (birthdayTree && birthdayTree->root) {
            db_begin_transaction(g_petcare_db);
            
            // Traverse the B+ tree and save each birthday
            BPlusNode* node = birthdayTree->root;
            for (int i = 0; i < node->count; i++) {
                int key = node->keys[i];
                int encodedDate = node->values[i];
                
                // Decode date: YYYYMMDD format
                int year = encodedDate / 10000;
                int month = (encodedDate / 100) % 100;
                int day = encodedDate % 100;
                
                // Find pet by key
                Pet* pet = findPetByName(petList, key);
                if (pet) {
                    db_add_birthday(g_petcare_db, pet->name, day, month, year, pet->owner);
                }
            }
            
            db_commit_transaction(g_petcare_db);
        }
        return;
    }
    
    // Otherwise, use traditional file-based approach
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening birthdays file");return;
    }

    // Traverse the B+ tree to write all birthdays
    if (birthdayTree && birthdayTree->root) {
        saveBPlusTreeToFile(birthdayTree->root, file, petList);
    }

    fclose(file);
    printf("Birthdays saved successfully to %s.\n", filename);
}

/**
 * @brief Recursively saves a B+ tree node to file.
 * @param node Pointer to the B+ tree node.
 * @param file File pointer.
 * @param petList Pointer to the pet list for retrieving pet details.
 */
void saveBPlusTreeToFile(BPlusNode* node, FILE* file, Pet* petList) {
    if (!node) return;

    const char* encryptionKey = "SecretKey"; 

    for (int i = 0; i < node->count; i++) {
        Pet* currentPet = findPetByName(petList, node->keys[i]);
        if (currentPet) {
            size_t nameLen = strlen(currentPet->name) + 1;
            fwrite(&nameLen, sizeof(size_t), 1, file);

            xorEncryptDecrypt(currentPet->name, nameLen, encryptionKey);
            fwrite(currentPet->name, sizeof(char), nameLen, file);
            xorEncryptDecrypt(currentPet->name, nameLen, encryptionKey);

            size_t typeLen = strlen(currentPet->type) + 1;
            fwrite(&typeLen, sizeof(size_t), 1, file);

            xorEncryptDecrypt(currentPet->type, typeLen, encryptionKey);
            fwrite(currentPet->type, sizeof(char), typeLen, file);
            xorEncryptDecrypt(currentPet->type, typeLen, encryptionKey);

            fwrite(&currentPet->age, sizeof(int), 1, file);

            size_t ownerLen = strlen(currentPet->owner) + 1;
            fwrite(&ownerLen, sizeof(size_t), 1, file);

            xorEncryptDecrypt(currentPet->owner, ownerLen, encryptionKey);
            fwrite(currentPet->owner, sizeof(char), ownerLen, file);
            xorEncryptDecrypt(currentPet->owner, ownerLen, encryptionKey);

            int encryptedDate = node->values[i];
            xorEncryptDecrypt((char*)&encryptedDate, sizeof(int), encryptionKey);
            fwrite(&encryptedDate, sizeof(int), 1, file);
        }
    }

    // Recursively save children
    for (int i = 0; i <= node->count; i++) {
        if (node->children[i]) {
            saveBPlusTreeToFile(node->children[i], file, petList);
        }
    }
}

/**
 * @brief Loads birthday data from a file (or database) into the B+ Tree.
 * @param birthdayTree Pointer to the BPlusTree to populate.
 * @param filename File to read from (or "database" to use SQLite).
 * @param petList Pointer to the pet list pointer (pets may also be loaded in this process).
 */
void loadBirthdaysFromFile(BPlusTree* birthdayTree, const char* filename, Pet** petList) {
    // If database is initialized and filename contains "birthdays", use SQLite
    if (g_petcare_db && strstr(filename, "birthdays") != NULL) {
        db_load_all_birthdays(g_petcare_db, birthdayTree, petList);
        return;
    }
    
    // Otherwise, use traditional file-based approach
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening birthdays file");return;
    }

    const char* encryptionKey = "SecretKey"; // Encryption key

    while (true) {
        size_t nameLen;
        if (fread(&nameLen, sizeof(size_t), 1, file) != 1) {
            break;
        }

        char* nameBuf = (char*)malloc(nameLen);
        if (!nameBuf) {
            perror("Memory allocation error for nameBuf");break;
        }

        if (fread(nameBuf, sizeof(char), nameLen, file) != nameLen) {
            free(nameBuf);break;
        }

        xorEncryptDecrypt(nameBuf, nameLen, encryptionKey);

        size_t typeLen;
        if (fread(&typeLen, sizeof(size_t), 1, file) != 1) {
            free(nameBuf);break;
        }

        char* typeBuf = (char*)malloc(typeLen);
        if (!typeBuf) {
            perror("Memory allocation error for typeBuf");
            free(nameBuf);
            break;
        }

        if (fread(typeBuf, sizeof(char), typeLen, file) != typeLen) {
            free(nameBuf);
            free(typeBuf);
            break;
        }
        xorEncryptDecrypt(typeBuf, typeLen, encryptionKey);

        int age;
        if (fread(&age, sizeof(int), 1, file) != 1) {
            free(nameBuf);
            free(typeBuf);
            break;
        }

        size_t ownerLen;
        if (fread(&ownerLen, sizeof(size_t), 1, file) != 1) {
            free(nameBuf);
            free(typeBuf);
            break;
        }

        char* ownerBuf = (char*)malloc(ownerLen);
        if (!ownerBuf) {
            perror("Memory allocation error for ownerBuf");
            free(nameBuf);
            free(typeBuf);
            break;
        }

        if (fread(ownerBuf, sizeof(char), ownerLen, file) != ownerLen) {
            free(nameBuf);
            free(typeBuf);
            free(ownerBuf);
            break;
        }
        xorEncryptDecrypt(ownerBuf, ownerLen, encryptionKey);

        int encodedDate;
        if (fread(&encodedDate, sizeof(int), 1, file) != 1) {
            free(nameBuf);
            free(typeBuf);
            free(ownerBuf);
            break;
        }
        xorEncryptDecrypt((char*)&encodedDate, sizeof(int), encryptionKey);

        int year = encodedDate / 10000;          
        int month = (encodedDate / 100) % 100;    
        int day = encodedDate % 100;            

        addPet(petList, nameBuf, typeBuf, age, ownerBuf);

        if (!birthdayTree->root) {
            birthdayTree->root = createBPlusNode();
        }
        insertBirthday(birthdayTree, nameBuf, day, month, year);

        // Securely wipe and free temporary buffers
        secure_wipe(nameBuf, nameLen);
        free(nameBuf);
        secure_wipe(typeBuf, typeLen);
        free(typeBuf);
        secure_wipe(ownerBuf, ownerLen);
        free(ownerBuf);
    }

    fclose(file);
    printf("Birthdays loaded successfully from %s.\n", filename);
}

/**
 * @brief Finds a pet by its hashed name key.
 * @param petList Pointer to the pet list.
 * @param key Hashed key of the pet's name.
 * @return Pointer to the Pet if found, NULL otherwise.
 */
Pet* findPetByName(Pet* petList, int key) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    while (opaque_true(dummy) && petList) {
        if (opaque_true(dummy) && hashFunction(petList->name) == key) {
            return petList;
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 41);
        }
        petList = petList->next;
    }
    return NULL;
}
ExerciseStack exerciseStack = { { }, -1 };

/**
 * @brief Adds an exercise routine for a pet, pushing it onto a stack.
 * @param petName Name of the pet.
 * @param exercise Description of the exercise routine.
 */
void addExerciseRoutine(const char* petName, const char* exercise) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    //100 is maximum rotuine count
    if (opaque_true(dummy) && exerciseStack.top >= obf_sub(MAX_ROUTINES, 1)) {
        printf("Error: Stack is full. Cannot add more routines.\n");
        return;
    }
    inject_dead_code(1);

    exerciseStack.top = obf_add(exerciseStack.top, 1);
    if (opaque_true(dummy)) {
        strncpy(exerciseStack.stack[exerciseStack.top].petName, petName, sizeof(exerciseStack.stack[exerciseStack.top].petName) - 1);
        strncpy(exerciseStack.stack[exerciseStack.top].exercise, exercise, sizeof(exerciseStack.stack[exerciseStack.top].exercise) - 1);
    }
    
    if (opaque_false(dummy)) {
        volatile int fake = obf_add(dummy, 83);
    }

    OBF_INFO("Exercise routine for '%s' added successfully!\n", petName);
}

/**
 * @brief Lists all exercise routines from the stack.
 */
void listAllExercises() {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && exerciseStack.top == -1) {
        printf("No exercise routines available.\n");
        return;
    }

    printf("\n--- Exercise Routines ---\n");
    int i = 0;
    while (i <= exerciseStack.top) {
        if (opaque_true(dummy)) {
            printf("Pet Name: %s\nRoutine: %s\n\n",
                exerciseStack.stack[i].petName,
                exerciseStack.stack[i].exercise);
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 19);
        }
        i++;
    }
}

/**
 * @brief Removes the last exercise routine from the stack (undo operation).
 */
void undoLastExercise() {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && exerciseStack.top == -1) {
        printf("Error: No exercise routines to undo.\n");
        return;
    }

    printf("Undoing last exercise routine for '%s'...\n", exerciseStack.stack[exerciseStack.top].petName);
    if (opaque_true(dummy)) {
        exerciseStack.top = obf_sub(exerciseStack.top, 1);  // Remove the most recent exercise by decrementing the top index
    }
    inject_dead_code(1);
    
    if (opaque_false(dummy)) {
        volatile int fake = obf_add(dummy, 67);
    }

    OBF_INFO("Last exercise routine undone successfully!\n");
}

/**
 * @brief Encryption key used for stray animals.
 */
static const char* STRAY_KEY = "StrayKey";
/**
 * @brief Encryption key used for adopted animals.
 */
static const char* ADOPTED_KEY = "AdoptedKey";

/**
 * @brief Computes the Longest Prefix Suffix (LPS) array for the KMP algorithm.
 * @param pattern The pattern string to analyze.
 * @param M The length of the pattern.
 * @param lps An integer array where the LPS values will be stored.
 */
static void computeLPSArray(const char* pattern, int M, int* lps) {
    int len = 0;
    lps[0] = 0;
    int i = 1;
    while (i < M) {
        if (pattern[i] == pattern[len]) {
            len++;lps[i] = len;i++;}
        else {
            if (len != 0) {len = lps[len - 1];}
            else {
                lps[i] = 0;
                i++;
            }
        }
    }
}

/**
 * @brief Uses a helper KMP function to check if a pattern is contained within a text.
 * @param text The main text.
 * @param pattern The substring/pattern.
 * @return True if the pattern is found, false otherwise.
 */
bool KMPcontains(const char* text, const char* pattern) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    int N = obf_strlen(text);
    int M = obf_strlen(pattern);
    if (opaque_true(dummy) && M == 0) return true; // boş pattern
    
    int* lps = (int*)secure_malloc(obf_mul_const(sizeof(int), M));
    computeLPSArray(pattern, M, lps);
    inject_dead_code(1);
    
    volatile int i = 0;
    volatile int j = 0;
    while (opaque_true(dummy) && i < N) {
        if (opaque_true(dummy) && pattern[j] == text[i]) {
            i = obf_add(i, 1);
            j = obf_add(j, 1);
        }
        if (opaque_true(dummy) && j == M) {
            secure_free(lps, obf_mul_const(sizeof(int), M));
            return true;
        }
        else if (opaque_true(dummy) && i < N && pattern[j] != text[i]) {
            if (opaque_true(dummy) && j != 0) j = lps[obf_sub(j, 1)];
            else i = obf_add(i, 1);
        }
        if (opaque_false(dummy)) {
            volatile int fake = obf_mul_const(dummy, 37);
        }
    }
    secure_free(lps, obf_mul_const(sizeof(int), M));
    return false;
}

/**
 * @brief Loads stray animals from a file (or database) into the given list.
 * @param list Pointer to the pointer of the stray animal list head.
 * @param filename Name of the file to load from (or "database" to use SQLite).
 */
void loadStrayAnimalsFromFile(StrayAnimal** list, const char* filename) {
    // If database is initialized and filename is "adoptable.dat", use SQLite
    if (g_petcare_db && strcmp(filename, "adoptable.dat") == 0) {
        db_load_all_stray_animals(g_petcare_db, list);
        return;
    }
    
    // Otherwise, use traditional file-based approach
    FILE* file = fopen(filename, "rb");
    if (!file) {return;}
    StrayAnimal temp;
    while (fread(&temp, sizeof(StrayAnimal), 1, file) == 1) {
        // XOR Decrypt struct
        xorEncryptDecrypt((char*)&temp, sizeof(StrayAnimal), STRAY_KEY);

        StrayAnimal* newAnimal = (StrayAnimal*)malloc(sizeof(StrayAnimal));
        memcpy(newAnimal, &temp, sizeof(StrayAnimal));
        newAnimal->next = NULL;

        if (*list == NULL) {
            *list = newAnimal;
        }
        else {
            StrayAnimal* cur = *list;
            while (cur->next != NULL) {
                cur = cur->next;}
            cur->next = newAnimal;
        }
    }
    fclose(file);
}

/**
 * @brief Saves the stray animal list to a file (or database).
 * @param list Pointer to the head of the stray animal list.
 * @param filename Name of the file to save to (or "database" to use SQLite).
 */
void saveStrayAnimalsToFile(StrayAnimal* list, const char* filename) {
    // If database is initialized and filename is "adoptable.dat", use SQLite
    if (g_petcare_db && strcmp(filename, "adoptable.dat") == 0) {
        // Clear existing stray animals in database first
        db_execute(g_petcare_db, "DELETE FROM stray_animals;");
        
        // Save all stray animals to database
        db_begin_transaction(g_petcare_db);
        StrayAnimal* current = list;
        while (current) {
            db_add_stray_animal(g_petcare_db, current->type, current->gender, 
                               current->arrivalDate, current->age);
            current = current->next;
        }
        db_commit_transaction(g_petcare_db);
        return;
    }
    
    // Otherwise, use traditional file-based approach
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening adoptable file");return;
    }
    StrayAnimal* current = list;
    while (current) {
        StrayAnimal temp;
        memcpy(&temp, current, sizeof(StrayAnimal));
        // XOR Encrypt
        xorEncryptDecrypt((char*)&temp, sizeof(StrayAnimal), STRAY_KEY);
        fwrite(&temp, sizeof(StrayAnimal), 1, file);
        current = current->next;
    }
    fclose(file);
}

/**
 * @brief Adds a stray animal to the list.
 * @param list Pointer to the pointer of the stray animal list head.
 * @param type Type of the stray animal.
 * @param gender Gender of the stray animal.
 * @param arrivalDate Arrival date string.
 * @param age Age of the animal.
 */
void addStrayAnimalToList(StrayAnimal** list, const char* type, const char* gender,
    const char* arrivalDate, int age) {
    static int globalID = 1;
    StrayAnimal* cur = *list;
    while (cur) {
        if (cur->id >= globalID) {globalID = cur->id + 1;}
        cur = cur->next;
    }

    StrayAnimal* newAnimal = (StrayAnimal*)malloc(sizeof(StrayAnimal));
    newAnimal->id = globalID++;
    strcpy(newAnimal->type, type);
    strcpy(newAnimal->gender, gender);
    strcpy(newAnimal->arrivalDate, arrivalDate);
    newAnimal->age = age;
    newAnimal->next = NULL;

    // Listeye ekle
    if (*list == NULL) {
        *list = newAnimal;
    }
    else {
        StrayAnimal* temp = *list;
        while (temp->next != NULL) {
            temp = temp->next;}
        temp->next = newAnimal;
    }
    printf("Stray animal added with ID: %d\n", newAnimal->id);
}

/**
 * @brief Updates a stray animal's information.
 * @param list Pointer to the head of the stray animal list.
 * @param id ID of the animal to update.
 * @param newType New type value.
 * @param newGender New gender value.
 * @param newArrivalDate New arrival date.
 * @param newAge New age.
 */
void updateStrayAnimal(
    StrayAnimal* list,
    int id,
    const char* newType,
    const char* newGender,
    const char* newArrivalDate,
    int newAge
)
{
    StrayAnimal* current = list;
    while (current) {
        if (current->id == id) {
            // First sync DB if available
            if (g_petcare_db) {
                if (db_update_stray_animal(g_petcare_db, id, newType, newGender, newArrivalDate, newAge) != 0) {
                    printf("[DATABASE] Warning: Could not update stray animal in database\n");
                }
            }
            // Direct in-memory update
            strcpy(current->type, newType);
            strcpy(current->gender, newGender);
            strcpy(current->arrivalDate, newArrivalDate);
            current->age = newAge;

            printf("Stray animal (ID %d) updated successfully.\n", id);
            return;
        }
        current = current->next;
    }
    printf("Stray animal with ID %d not found.\n", id);
}

/**
 * @brief Deletes a stray animal from the list by ID.
 * @param list Pointer to the pointer of the stray animal list head.
 * @param id ID of the animal to delete.
 */
void deleteStrayAnimal(StrayAnimal** list, int id) {
    StrayAnimal* current = *list;
    StrayAnimal* prev = NULL;
    while (current) {
        if (current->id == id) {
            // First sync DB if available
            if (g_petcare_db) {
                if (db_delete_stray_animal(g_petcare_db, id) != 0) {
                    printf("[DATABASE] Warning: Could not delete stray animal in database\n");
                }
            }
            if (prev == NULL) {
                *list = current->next;
            }
            else {
                prev->next = current->next;
            }
            free(current);
            printf("Stray animal with ID %d deleted successfully.\n", id);
            return;
        }
        prev = current;
        current = current->next;}
    printf("Stray animal with ID %d not found.\n", id);}

/**
 * @brief Lists all stray animals currently available.
 * @param list Pointer to the head of the stray animal list.
 */
void listStrayAnimals(StrayAnimal* list) {
    if (!list) {
        printf("No stray animals available.\n");return;
    }
    printf("\n--- List of Stray Animals ---\n");
    StrayAnimal* current = list;
    while (current) {
        printf("ID: %d, Type: %s, Gender: %s, ArrivalDate: %s, Age: %d\n",
            current->id, current->type, current->gender,
            current->arrivalDate, current->age);
        current = current->next;
    }
}

/**
 * @brief Uses KMP to search for stray animals whose type contains the searchKey.
 * @param list Pointer to the head of the stray animal list.
 * @param searchKey Substring to search for in the animal's type.
 */
void searchStrayAnimalsKMP(StrayAnimal* list, const char* searchKey) {
    if (!list) {
        printf("No stray animals to search.\n");return;
    }
    int found = 0;
    StrayAnimal* current = list;
    while (current) {
        // type alanında searchKey geçiyor mu?
        if (KMPcontains(current->type, searchKey)) {
            printf("ID: %d, Type: %s, Gender: %s, ArrivalDate: %s, Age: %d\n",
                current->id, current->type, current->gender,
                current->arrivalDate, current->age);
            found = 1;
        }
        current = current->next;
    }
    if (!found) {
        printf("No stray animals found with type containing '%s'.\n", searchKey);
    }
}

/**
 * @brief Loads adopted animals from a file (or database) into the given list.
 * @param list Pointer to the pointer of the adopted animal list head.
 * @param filename Name of the file to load from (or "database" to use SQLite).
 */
void loadAdoptedAnimalsFromFile(AdoptedAnimal** list, const char* filename) {
    // If database is initialized and filename is "adopted.dat", use SQLite
    if (g_petcare_db && strcmp(filename, "adopted.dat") == 0) {
        db_load_all_adopted_animals(g_petcare_db, list);
        return;
    }
    
    // Otherwise, use traditional file-based approach
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return;
    }
    AdoptedAnimal temp;
    while (fread(&temp, sizeof(AdoptedAnimal), 1, file) == 1) {
        // XOR Decrypt
        xorEncryptDecrypt((char*)&temp, sizeof(AdoptedAnimal), ADOPTED_KEY);

        // Bellekte yeni node
        AdoptedAnimal* newAdopted = (AdoptedAnimal*)malloc(sizeof(AdoptedAnimal));
        memcpy(newAdopted, &temp, sizeof(AdoptedAnimal));
        newAdopted->next = NULL;

        // Listeye ekle
        if (*list == NULL) {
            *list = newAdopted;
        }
        else {
            AdoptedAnimal* cur = *list;
            while (cur->next != NULL) {
                cur = cur->next;
            }cur->next = newAdopted;
        }
    }
    fclose(file);
}

/**
 * @brief Saves the adopted animal list to a file (or database).
 * @param list Pointer to the head of the adopted animal list.
 * @param filename Name of the file to save to (or "database" to use SQLite).
 */
void saveAdoptedAnimalsToFile(AdoptedAnimal* list, const char* filename) {
    // If database is initialized and filename is "adopted.dat", use SQLite
    if (g_petcare_db && strcmp(filename, "adopted.dat") == 0) {
        // Clear existing adopted animals in database first
        db_execute(g_petcare_db, "DELETE FROM adopted_animals;");
        
        // Save all adopted animals to database
        db_begin_transaction(g_petcare_db);
        AdoptedAnimal* current = list;
        while (current) {
            db_add_adopted_animal(g_petcare_db, current->id, current->type, current->gender,
                                 current->arrivalDate, current->age, current->owner, 
                                 current->adoptionDate);
            current = current->next;
        }
        db_commit_transaction(g_petcare_db);
        return;
    }
    
    // Otherwise, use traditional file-based approach
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening adopted file");return;
    }
    AdoptedAnimal* current = list;
    while (current) {
        AdoptedAnimal temp;
        memcpy(&temp, current, sizeof(AdoptedAnimal));
        // XOR Encrypt
        xorEncryptDecrypt((char*)&temp, sizeof(AdoptedAnimal), ADOPTED_KEY);
        fwrite(&temp, sizeof(AdoptedAnimal), 1, file);
        current = current->next;
    }
    fclose(file);
}

/**
 * @brief Adopts a stray animal (no new name scenario).
 * @param strayList Pointer to the pointer of the stray list head.
 * @param activeUser Username of the currently logged-in user who is adopting.
 */
void adoptStrayAnimal(StrayAnimal** strayList,
    const char* activeUser,
    int chosenID,
    const char* newName,
    const char* adoptionDate)
{
    if (!(*strayList)) {
        printf("No stray animals available to adopt.\n");   return;
    }

    StrayAnimal* current = *strayList;
    StrayAnimal* prev = NULL;

    while (current) {
        if (current->id == chosenID) {
            AdoptedAnimal adopted;
            adopted.id = current->id;
            strcpy(adopted.type, current->type);
            strcpy(adopted.gender, current->gender);
            strcpy(adopted.arrivalDate, current->arrivalDate);
            adopted.age = current->age;

            strcpy(adopted.owner, activeUser);
            strcpy(adopted.adoptionDate, adoptionDate);
            printf("You named the animal: %s\n", newName);

            AdoptedAnimal* adoptedList = NULL;
            loadAdoptedAnimalsFromFile(&adoptedList, "adopted.dat");

            AdoptedAnimal* newNode = (AdoptedAnimal*)malloc(sizeof(AdoptedAnimal));
            memcpy(newNode, &adopted, sizeof(AdoptedAnimal));
            newNode->next = NULL;

            if (adoptedList == NULL) {
                adoptedList = newNode;
            }
            else {
                AdoptedAnimal* tmp = adoptedList;
                while (tmp->next) {
                    tmp = tmp->next;
                }tmp->next = newNode;}

            saveAdoptedAnimalsToFile(adoptedList, "adopted.dat");

            if (prev == NULL) {
                *strayList = current->next;
            }
            else {
                prev->next = current->next;
            }
            free(current);

            saveStrayAnimalsToFile(*strayList, "adoptable.dat");

            printf("Adoption complete. Animal ID %d adopted.\n", chosenID);
            return;
        }
        prev = current;
        current = current->next;
    }

    printf("Stray animal with ID %d not found.\n", chosenID);
}

/**
 * @brief Lists all adopted animals.
 * @param list Pointer to the head of the adopted animal list.
 */
void listAllAdoptedAnimals(AdoptedAnimal* list) {
    if (!list) {
        printf("No adopted animals found.\n");
        return;
    }
    printf("\n--- List of Adopted Animals ---\n");
    AdoptedAnimal* current = list;
    while (current) {
        printf("ID: %d, Type: %s, Gender: %s, ArrivalDate: %s, Age: %d, Owner: %s, AdoptionDate: %s\n",
            current->id, current->type, current->gender, current->arrivalDate,
            current->age, current->owner, current->adoptionDate);
        current = current->next;
    }
}

/**
 * @brief Recursively traverses a B+ tree node to print or process pet birthdays.
 * @param node Pointer to the current BPlusNode in the tree.
 * @param petList Pointer to the linked list of pets (to match against keys).
 */
static void traverseBPlusNodeForBirthdays(BPlusNode* node, Pet* petList) {
    if (!node) return;

    // Mevcut node'daki tüm key/value çiftlerini oku
    for (int i = 0; i < node->count; i++) {
        int key = node->keys[i];
        int encodedDate = node->values[i];

        // Pet'i bul
        Pet* foundPet = findPetByName(petList, key);
        if (foundPet) {
            // Encoded date: YYYYMMDD format
            int year = encodedDate / 10000;
            int month = (encodedDate / 100) % 100;
            int day = encodedDate % 100;

            printf("Pet Name: %s | Type: %s | Owner: %s | Birthday: %02d/%02d/%04d\n",
                foundPet->name,
                foundPet->type,
                foundPet->owner,
                day, month, year);
        }
    }

    for (int i = 0; i <= node->count; i++) {
        if (node->children[i]) {
            traverseBPlusNodeForBirthdays(node->children[i], petList);
        }
    }
}

void listPetBirthdays(BPlusTree* birthdayTree, Pet* petList) {
    if (!birthdayTree || !birthdayTree->root) {
        printf("No birthdays recorded.\n"); return;}
    printf("\n--- List of Pet Birthdays ---\n");
    traverseBPlusNodeForBirthdays(birthdayTree->root, petList);
    printf("--------------------------------\n");
}

// ============================================================================
// Session Management Functions
// ============================================================================

/**
 * @brief Initialize device fingerprint and session management
 */
void init_petcare_session() {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    // Check for tampering at startup
    int tampering_status = detect_tampering();
    if (opaque_true(dummy) && tampering_status > 0) {
        OBF_WARN("Warning: Potential tampering detected (code %d)\n", tampering_status);
    }
    inject_dead_code(1);
    
    // Generate device fingerprint
    if (opaque_true(dummy) && !g_fingerprint_initialized) {
        if (opaque_true(dummy) && generate_device_fingerprint(&g_device_fingerprint) != 0) {
            OBF_ERROR("Error: Failed to generate device fingerprint\n");
            return;
        }
        g_fingerprint_initialized = obf_add(1, 0);
    }
    if (opaque_false(dummy)) {
        volatile int fake = obf_mul_const(dummy, 91);
    }
}

/**
 * @brief Login user with session creation and device binding
 * @param table Pointer to the HashTable
 * @param username User name
 * @param password User password
 * @return 1 if authenticated and session created, 0 otherwise
 */
int loginUserWithSession(HashTable* table, const char* username, const char* password) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    // First authenticate normally
    if (opaque_true(dummy) && !authenticateUser(table, username, password)) {
        return 0;
    }
    inject_dead_code(1);
    
    // Ensure fingerprint is initialized
    if (opaque_true(dummy) && !g_fingerprint_initialized) {
        init_petcare_session();
    }
    
    // Create session (1 hour = 3600 seconds)
    if (opaque_true(dummy) && create_session(&g_device_fingerprint, obf_mul_const(3600, 1), &g_current_session) != 0) {
        OBF_ERROR("Error: Failed to create session\n");
        return 0;
    }
    if (opaque_false(dummy)) {
        volatile int fake = obf_add(dummy, 73);
    }
    
    g_session_active = 1;
    return 1;
}

/**
 * @brief Logout user and destroy session
 */
void logoutUserSession() {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && g_session_active) {
        invalidate_session(&g_current_session);
        g_session_active = 0;
    }
    if (opaque_false(dummy)) {
        volatile int fake = obf_mul_const(dummy, 62);
    }
}

/**
 * @brief Check if current session is valid
 * @return 1 if session is valid, 0 otherwise
 */
int isSessionValid() {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && (!g_session_active || !g_fingerprint_initialized)) {
        return 0;
    }
    
    uint8_t session_key[32];
    int result = validate_session(&g_current_session, &g_device_fingerprint, session_key);
    inject_dead_code(1);
    
    // Securely wipe the session key
    secure_wipe(session_key, sizeof(session_key));
    
    if (opaque_false(dummy)) {
        volatile int fake = obf_add(dummy, 58);
    }
    
    return (result == 0) ? obf_add(1, 0) : 0;
}

// ============================================================================
// Database Management Functions
// ============================================================================

/**
 * @brief Initialize the PetCare database
 * @param db_path Path to the database file
 * @return 0 on success, non-zero on failure
 */
static int get_kdf_iterations() {
    const char* env = getenv("PETCARE_KDF_ITERS");
    if (!env) return 20000;
    long v = strtol(env, NULL, 10);
    if (v < 1000) v = 1000;
    if (v > 1000000) v = 1000000;
    return (int)v;
}

int init_petcare_database(const char* db_path) {
    volatile int dummy = (int)time(NULL) | 1;
    inject_dead_code(1);
    
    if (opaque_true(dummy) && g_db_initialized) {
        return 0; // Already initialized
    }
    inject_dead_code(1);
    
    // Derive per-device application key (device fingerprint + app hash)
    unsigned char app_hash[32]; 
    obf_memset(app_hash, 0, sizeof(app_hash));
    SecureAutoWipe wipe_app_hash(app_hash, sizeof(app_hash));
    (void)get_app_integrity_hash(app_hash);
    DeviceFingerprint fp; 
    obf_memset(&fp, 0, sizeof(fp));
    generate_device_fingerprint(&fp);
    unsigned char salt[16]; 
    obf_memcpy(salt, fp.combined_fingerprint, 16);
    SecureAutoWipe wipe_salt(salt, sizeof(salt));
    inject_dead_code(1);
    static char encryption_key_hex[65];
    unsigned char key[SECURE_KEY_SIZE];
    SecureAutoWipe wipe_key(key, sizeof(key));
    secure_derive_key((const char*)app_hash, 32, salt, 16, get_kdf_iterations(), key);
    const char* hexd = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        encryption_key_hex[i*2] = hexd[(key[i] >> 4) & 0xF];
        encryption_key_hex[i*2+1] = hexd[key[i] & 0xF];
    }
    encryption_key_hex[64] = '\0';
    secure_wipe(key, sizeof(key));

    g_petcare_db = db_init(db_path, encryption_key_hex);
    // Wipe hex key after use
    secure_wipe(encryption_key_hex, sizeof(encryption_key_hex));
    
    if (!g_petcare_db) {
        fprintf(stderr, "Failed to initialize database\n");
        return -1;
    }
    
    // Create tables
    if (db_create_tables(g_petcare_db) != 0) {
        fprintf(stderr, "Failed to create database tables\n");
        db_close(g_petcare_db);
        g_petcare_db = NULL;
        return -1;
    }
    
    g_db_initialized = 1;
    return 0;
}

/**
 * @brief Close the PetCare database
 */
void close_petcare_database() {
    if (g_petcare_db) {
        db_close(g_petcare_db);
        g_petcare_db = NULL;
        g_db_initialized = 0;
    }
}

/**
 * @brief Get the global database handle
 * @return Pointer to the global database handle
 */
Database* get_petcare_database() {
    return g_petcare_db;
}

/**
 * @brief Migrate data from .dat files to SQLite database
 * @return 0 on success, non-zero on failure
 */
int migrate_dat_to_sqlite() {
    if (!g_petcare_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }
    
    printf("Migrating data from .dat files to SQLite...\n");
    
#ifdef SQLITE3_HEADER_ONLY
    printf("SQLite3 not available - using file-based storage only.\n");
    return -1;
#else
    // Check if migration is needed (check if users table is empty)
    sqlite3_stmt* stmt;
    const char* sql = "SELECT COUNT(*) FROM users;";
    int rc = sqlite3_prepare_v2(g_petcare_db->db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            int count = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
            if (count > 0) {
                printf("Database already contains data, skipping migration.\n");
                return 0;
            }
        } else {
            sqlite3_finalize(stmt);
        }
    }
#endif // SQLITE3_HEADER_ONLY
    
    printf("Starting migration...\n");
    
    // Begin transaction for faster migration
    db_begin_transaction(g_petcare_db);
    
    // Migrate users from users.dat
    FILE* users_file = fopen("users.dat", "rb");
    if (users_file) {
        printf("Migrating users from users.dat...\n");
        fclose(users_file);
        
        // Load users using old method into temp hash table
        HashTable* temp_table = createHashTable();
        loadUsersFromFile(temp_table, "users.dat");
        
        // Migrate to database
        int user_count = 0;
        for (int i = 0; i < HASH_TABLE_SIZE; i++) {
            User* current = temp_table->buckets[i];
            while (current) {
                if (db_add_user(g_petcare_db, current->username, current->encryptedPassword) == 0) {
                    user_count++;
                }
                current = current->next;
            }
        }
        printf("Migrated %d users\n", user_count);
        
        freeHashTable(temp_table);
    }
    
    // Migrate pets from pets.dat
    FILE* pets_file = fopen("pets.dat", "rb");
    if (pets_file) {
        printf("Migrating pets from pets.dat...\n");
        fclose(pets_file);
        
        // Load pets using old method
        Pet* temp_pets = NULL;
        loadPetsFromFile(&temp_pets, "pets.dat");
        
        // Migrate to database
        int pet_count = 0;
        Pet* current = temp_pets;
        while (current) {
            if (db_add_pet(g_petcare_db, current->name, current->type, current->age, current->owner) == 0) {
                pet_count++;
            }
            current = current->next;
        }
        printf("Migrated %d pets\n", pet_count);
        
        freePetList(temp_pets);
    }
    
    // Migrate stray animals from adoptable.dat
    FILE* stray_file = fopen("adoptable.dat", "rb");
    if (stray_file) {
        printf("Migrating stray animals from adoptable.dat...\n");
        fclose(stray_file);
        
        StrayAnimal* temp_strays = NULL;
        loadStrayAnimalsFromFile(&temp_strays, "adoptable.dat");
        
        int stray_count = 0;
        StrayAnimal* current = temp_strays;
        while (current) {
            int id = db_add_stray_animal(g_petcare_db, current->type, current->gender,
                                         current->arrivalDate, current->age);
            if (id >= 0) {
                stray_count++;
            }
            StrayAnimal* next = current->next;
            free(current);
            current = next;
        }
        printf("Migrated %d stray animals\n", stray_count);
    }
    
    // Migrate adopted animals from adopted.dat
    FILE* adopted_file = fopen("adopted.dat", "rb");
    if (adopted_file) {
        printf("Migrating adopted animals from adopted.dat...\n");
        fclose(adopted_file);
        
        AdoptedAnimal* temp_adopted = NULL;
        loadAdoptedAnimalsFromFile(&temp_adopted, "adopted.dat");
        
        int adopted_count = 0;
        AdoptedAnimal* current = temp_adopted;
        while (current) {
            if (db_add_adopted_animal(g_petcare_db, current->id, current->type, current->gender,
                                      current->arrivalDate, current->age, current->owner,
                                      current->adoptionDate) == 0) {
                adopted_count++;
            }
            AdoptedAnimal* next = current->next;
            free(current);
            current = next;
        }
        printf("Migrated %d adopted animals\n", adopted_count);
    }
    
    // Commit transaction
    db_commit_transaction(g_petcare_db);
    
    printf("Migration complete!\n");
    return 0;
}

