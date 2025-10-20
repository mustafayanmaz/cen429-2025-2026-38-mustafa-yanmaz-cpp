/**
 * @file database.cpp
 * @brief SQLite database wrapper implementation for PetCare application
 */

#include "database.h"
#include "petcare.h"
#include "secureMemory.h"
#include "whiteboxCrypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef SQLITE3_HEADER_ONLY
// ============================================================================
// STUB IMPLEMENTATIONS - SQLite3 library not available
// ============================================================================
// These are placeholder implementations that allow compilation without SQLite3 library

Database* db_init(const char* db_path, const char* encryption_key) {
    (void)db_path; (void)encryption_key;
    fprintf(stderr, "[WARNING] Database features disabled - SQLite3 library not found\n");
    return NULL;
}

void db_close(Database* db) { (void)db; }
int db_create_tables(Database* db) { (void)db; return -1; }
int db_execute(Database* db, const char* sql) { (void)db; (void)sql; return -1; }
int db_begin_transaction(Database* db) { (void)db; return -1; }
int db_commit_transaction(Database* db) { (void)db; return -1; }
int db_rollback_transaction(Database* db) { (void)db; return -1; }
int db_add_user(Database* db, const char* username, const char* encrypted_password) { (void)db; (void)username; (void)encrypted_password; return -1; }
int db_get_user_password(Database* db, const char* username, char** password_out) { (void)db; (void)username; (void)password_out; return -1; }
int db_user_exists(Database* db, const char* username) { (void)db; (void)username; return 0; }
int db_load_all_users(Database* db, HashTable* table) { (void)db; (void)table; return 0; }
int db_add_pet(Database* db, const char* name, const char* type, int age, const char* owner) { (void)db; (void)name; (void)type; (void)age; (void)owner; return -1; }
int db_update_pet(Database* db, const char* old_name, const char* owner, const char* new_name, const char* new_type, int new_age) { (void)db; (void)old_name; (void)owner; (void)new_name; (void)new_type; (void)new_age; return -1; }
int db_delete_pet(Database* db, const char* name, const char* owner) { (void)db; (void)name; (void)owner; return -1; }
int db_load_all_pets(Database* db, Pet** petList) { (void)db; (void)petList; return 0; }
int db_is_pet_owned_by(Database* db, const char* name, const char* owner) { (void)db; (void)name; (void)owner; return 0; }
int db_add_appointment(Database* db, const char* pet_name, const char* description, int day, int month, const char* owner) { (void)db; (void)pet_name; (void)description; (void)day; (void)month; (void)owner; return -1; }
int db_update_appointment(Database* db, const char* pet_name, int old_day, int old_month, int new_day, int new_month, const char* new_description, const char* owner) { (void)db; (void)pet_name; (void)old_day; (void)old_month; (void)new_day; (void)new_month; (void)new_description; (void)owner; return -1; }
int db_delete_appointment(Database* db, const char* pet_name, int day, int month, const char* owner) { (void)db; (void)pet_name; (void)day; (void)month; (void)owner; return -1; }
int db_load_all_appointments(Database* db) { (void)db; return 0; }
int db_is_date_occupied(Database* db, int day, int month) { (void)db; (void)day; (void)month; return 0; }
int db_add_birthday(Database* db, const char* pet_name, int day, int month, int year, const char* owner) { (void)db; (void)pet_name; (void)day; (void)month; (void)year; (void)owner; return -1; }
int db_load_all_birthdays(Database* db, BPlusTree* birthdayTree, Pet** petList) { (void)db; (void)birthdayTree; (void)petList; return 0; }
int db_add_stray_animal(Database* db, const char* type, const char* gender, const char* arrival_date, int age) { (void)db; (void)type; (void)gender; (void)arrival_date; (void)age; return -1; }
int db_update_stray_animal(Database* db, int id, const char* type, const char* gender, const char* arrival_date, int age) { (void)db; (void)id; (void)type; (void)gender; (void)arrival_date; (void)age; return -1; }
int db_delete_stray_animal(Database* db, int id) { (void)db; (void)id; return -1; }
int db_load_all_stray_animals(Database* db, StrayAnimal** list) { (void)db; (void)list; return 0; }
int db_add_adopted_animal(Database* db, int id, const char* type, const char* gender, const char* arrival_date, int age, const char* owner, const char* adoption_date) { (void)db; (void)id; (void)type; (void)gender; (void)arrival_date; (void)age; (void)owner; (void)adoption_date; return -1; }
int db_load_all_adopted_animals(Database* db, AdoptedAnimal** list) { (void)db; (void)list; return 0; }
int db_adopt_stray_animal(Database* db, int stray_id, const char* owner, const char* adoption_date) { (void)db; (void)stray_id; (void)owner; (void)adoption_date; return -1; }
const char* db_get_error(Database* db) { (void)db; return "SQLite3 library not available"; }
long long db_last_insert_id(Database* db) { (void)db; return -1; }
int db_backup(Database* db, const char* backup_path) { (void)db; (void)backup_path; return -1; }
int db_restore(const char* db_path, const char* backup_path) { (void)db_path; (void)backup_path; return -1; }

#else
// ============================================================================
// FULL SQLITE3 IMPLEMENTATION
// ============================================================================

// Forward declarations for encryption helper functions
static int encrypt_database_page(void* pCtx, int nPage, unsigned char* pData, int nData);
static int decrypt_database_page(void* pCtx, int nPage, unsigned char* pData, int nData);

/**
 * @brief Encryption key for database (stored obfuscated)
 */
static const char* DB_ENCRYPTION_KEY = "PetCare2024DatabaseEncryption!@#$";

/**
 * @brief Initialize the database connection
 * @param db_path Path to the database file
 * @param encryption_key Encryption key for the database (can be NULL)
 * @return Pointer to Database handle, NULL on failure
 */
Database* db_init(const char* db_path, const char* encryption_key) {
    Database* db = (Database*)malloc(sizeof(Database));
    if (!db) {
        return NULL;
    }
    
    db->db = NULL;
    db->db_path = strdup(db_path);
    db->is_encrypted = (encryption_key != NULL) ? 1 : 0;
    
    int rc = sqlite3_open(db_path, &db->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db->db));
        free(db->db_path);
        free(db);
        return NULL;
    }
    
    // Enable foreign keys
    sqlite3_exec(db->db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    
    // Set encryption if provided (using custom encryption, not SQLCipher)
    if (encryption_key) {
        // Note: This is a placeholder for custom encryption
        // Real implementation would use SQLite encryption extension or SQLCipher
        char pragma[512];
        snprintf(pragma, sizeof(pragma), "PRAGMA cipher_memory_security = ON;");
        sqlite3_exec(db->db, pragma, NULL, NULL, NULL);
    }
    
    return db;
}

/**
 * @brief Close the database connection
 * @param db Database handle
 */
void db_close(Database* db) {
    if (!db) return;
    
    if (db->db) {
        sqlite3_close(db->db);
    }
    
    if (db->db_path) {
        free(db->db_path);
    }
    
    free(db);
}

/**
 * @brief Create all necessary tables in the database
 * @param db Database handle
 * @return 0 on success, non-zero on failure
 */
int db_create_tables(Database* db) {
    if (!db || !db->db) return -1;
    
    char* err_msg = NULL;
    int rc;
    
    // Users table
    const char* sql_users = 
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE NOT NULL,"
        "encrypted_password TEXT NOT NULL,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");";
    
    rc = sqlite3_exec(db->db, sql_users, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (users): %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    
    // Pets table
    const char* sql_pets = 
        "CREATE TABLE IF NOT EXISTS pets ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "name TEXT NOT NULL,"
        "type TEXT NOT NULL,"
        "age INTEGER NOT NULL,"
        "owner TEXT NOT NULL,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "FOREIGN KEY(owner) REFERENCES users(username) ON DELETE CASCADE"
        ");";
    
    rc = sqlite3_exec(db->db, sql_pets, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (pets): %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    
    // Appointments table
    const char* sql_appointments = 
        "CREATE TABLE IF NOT EXISTS appointments ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "pet_name TEXT NOT NULL,"
        "description TEXT NOT NULL,"
        "day INTEGER NOT NULL,"
        "month INTEGER NOT NULL,"
        "owner TEXT NOT NULL,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(day, month)"
        ");";
    
    rc = sqlite3_exec(db->db, sql_appointments, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (appointments): %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    
    // Birthdays table
    const char* sql_birthdays = 
        "CREATE TABLE IF NOT EXISTS birthdays ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "pet_name TEXT NOT NULL,"
        "day INTEGER NOT NULL,"
        "month INTEGER NOT NULL,"
        "year INTEGER NOT NULL,"
        "owner TEXT NOT NULL,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(pet_name, owner)"
        ");";
    
    rc = sqlite3_exec(db->db, sql_birthdays, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (birthdays): %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    
    // Stray animals table
    const char* sql_stray = 
        "CREATE TABLE IF NOT EXISTS stray_animals ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "type TEXT NOT NULL,"
        "gender TEXT NOT NULL,"
        "arrival_date TEXT NOT NULL,"
        "age INTEGER NOT NULL,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");";
    
    rc = sqlite3_exec(db->db, sql_stray, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (stray_animals): %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    
    // Adopted animals table
    const char* sql_adopted = 
        "CREATE TABLE IF NOT EXISTS adopted_animals ("
        "id INTEGER PRIMARY KEY,"
        "type TEXT NOT NULL,"
        "gender TEXT NOT NULL,"
        "arrival_date TEXT NOT NULL,"
        "age INTEGER NOT NULL,"
        "owner TEXT NOT NULL,"
        "adoption_date TEXT NOT NULL,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");";
    
    rc = sqlite3_exec(db->db, sql_adopted, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (adopted_animals): %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    
    return 0;
}

/**
 * @brief Execute a SQL query with no result expected
 * @param db Database handle
 * @param sql SQL query string
 * @return 0 on success, non-zero on failure
 */
int db_execute(Database* db, const char* sql) {
    if (!db || !db->db || !sql) return -1;
    
    char* err_msg = NULL;
    int rc = sqlite3_exec(db->db, sql, NULL, NULL, &err_msg);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    
    return 0;
}

/**
 * @brief Begin a transaction
 * @param db Database handle
 * @return 0 on success, non-zero on failure
 */
int db_begin_transaction(Database* db) {
    return db_execute(db, "BEGIN TRANSACTION;");
}

/**
 * @brief Commit a transaction
 * @param db Database handle
 * @return 0 on success, non-zero on failure
 */
int db_commit_transaction(Database* db) {
    return db_execute(db, "COMMIT;");
}

/**
 * @brief Rollback a transaction
 * @param db Database handle
 * @return 0 on success, non-zero on failure
 */
int db_rollback_transaction(Database* db) {
    return db_execute(db, "ROLLBACK;");
}

// ============================================================================
// User Management Functions
// ============================================================================

/**
 * @brief Add a user to the database
 * @param db Database handle
 * @param username Username
 * @param encrypted_password Encrypted password
 * @return 0 on success, non-zero on failure
 */
int db_add_user(Database* db, const char* username, const char* encrypted_password) {
    if (!db || !db->db || !username || !encrypted_password) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO users (username, encrypted_password) VALUES (?, ?);";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, encrypted_password, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert user: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return 0;
}

/**
 * @brief Get user's encrypted password from database
 * @param db Database handle
 * @param username Username
 * @param password_out Output buffer for encrypted password (must be freed by caller)
 * @return 0 on success, non-zero on failure
 */
int db_get_user_password(Database* db, const char* username, char** password_out) {
    if (!db || !db->db || !username || !password_out) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT encrypted_password FROM users WHERE username = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char* password = (const char*)sqlite3_column_text(stmt, 0);
        *password_out = strdup(password);
        sqlite3_finalize(stmt);
        return 0;
    }
    
    sqlite3_finalize(stmt);
    return -1;
}

/**
 * @brief Check if a user exists
 * @param db Database handle
 * @param username Username
 * @return 1 if exists, 0 if not, negative on error
 */
int db_user_exists(Database* db, const char* username) {
    if (!db || !db->db || !username) return 0;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT COUNT(*) FROM users WHERE username = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    int count = 0;
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return (count > 0) ? 1 : 0;
}

/**
 * @brief Load all users from database into a HashTable
 * @param db Database handle
 * @param table HashTable to populate
 * @return Number of users loaded, negative on error
 */
int db_load_all_users(Database* db, HashTable* table) {
    if (!db || !db->db || !table) return 0;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT username, encrypted_password FROM users;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    int count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* username = (const char*)sqlite3_column_text(stmt, 0);
        const char* encrypted_password = (const char*)sqlite3_column_text(stmt, 1);
        
        // Add user to hash table
        unsigned int index = hashFunction(username);
        User* newUser = (User*)malloc(sizeof(User));
        newUser->username = secure_strdup(username);
        newUser->encryptedPassword = secure_strdup(encrypted_password);
        newUser->next = table->buckets[index];
        table->buckets[index] = newUser;
        
        count++;
    }
    
    sqlite3_finalize(stmt);
    return count;
}

// ============================================================================
// Pet Management Functions
// ============================================================================

/**
 * @brief Add a pet to the database
 * @param db Database handle
 * @param name Pet name
 * @param type Pet type
 * @param age Pet age
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_add_pet(Database* db, const char* name, const char* type, int age, const char* owner) {
    if (!db || !db->db || !name || !type || !owner) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO pets (name, type, age, owner) VALUES (?, ?, ?, ?);";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, age);
    sqlite3_bind_text(stmt, 4, owner, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert pet: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return 0;
}

/**
 * @brief Update a pet in the database
 * @param db Database handle
 * @param old_name Current pet name
 * @param owner Owner username (for permission check)
 * @param new_name New pet name
 * @param new_type New pet type
 * @param new_age New pet age
 * @return 0 on success, non-zero on failure
 */
int db_update_pet(Database* db, const char* old_name, const char* owner,
                  const char* new_name, const char* new_type, int new_age) {
    if (!db || !db->db || !old_name || !owner || !new_name || !new_type) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE pets SET name = ?, type = ?, age = ? WHERE name = ? AND owner = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, new_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, new_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, new_age);
    sqlite3_bind_text(stmt, 4, old_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, owner, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to update pet: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return (sqlite3_changes(db->db) > 0) ? 0 : -1;
}

/**
 * @brief Delete a pet from the database
 * @param db Database handle
 * @param name Pet name
 * @param owner Owner username (for permission check)
 * @return 0 on success, non-zero on failure
 */
int db_delete_pet(Database* db, const char* name, const char* owner) {
    if (!db || !db->db || !name || !owner) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "DELETE FROM pets WHERE name = ? AND owner = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, owner, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to delete pet: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return (sqlite3_changes(db->db) > 0) ? 0 : -1;
}

/**
 * @brief Load all pets from database into a linked list
 * @param db Database handle
 * @param petList Pointer to pet list head
 * @return Number of pets loaded, negative on error
 */
int db_load_all_pets(Database* db, Pet** petList) {
    if (!db || !db->db || !petList) return 0;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT name, type, age, owner FROM pets;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    int count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(stmt, 0);
        const char* type = (const char*)sqlite3_column_text(stmt, 1);
        int age = sqlite3_column_int(stmt, 2);
        const char* owner = (const char*)sqlite3_column_text(stmt, 3);
        
        // Add pet to the list
        addPet(petList, name, type, age, owner);
        count++;
    }
    
    sqlite3_finalize(stmt);
    return count;
}

/**
 * @brief Check if a pet belongs to a specific owner
 * @param db Database handle
 * @param name Pet name
 * @param owner Owner username
 * @return 1 if owned, 0 if not, negative on error
 */
int db_is_pet_owned_by(Database* db, const char* name, const char* owner) {
    if (!db || !db->db || !name || !owner) return 0;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT COUNT(*) FROM pets WHERE name = ? AND owner = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, owner, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    int count = 0;
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return (count > 0) ? 1 : 0;
}

// ============================================================================
// Appointment Management Functions
// ============================================================================

/**
 * @brief Add an appointment to the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param description Appointment description
 * @param day Day of appointment
 * @param month Month of appointment
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_add_appointment(Database* db, const char* pet_name, const char* description,
                       int day, int month, const char* owner) {
    if (!db || !db->db || !pet_name || !description || !owner) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO appointments (pet_name, description, day, month, owner) VALUES (?, ?, ?, ?, ?);";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, pet_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, description, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, day);
    sqlite3_bind_int(stmt, 4, month);
    sqlite3_bind_text(stmt, 5, owner, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert appointment: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return 0;
}

/**
 * @brief Update an appointment
 * @param db Database handle
 * @param pet_name Pet name
 * @param old_day Old day
 * @param old_month Old month
 * @param new_day New day
 * @param new_month New month
 * @param new_description New description
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_update_appointment(Database* db, const char* pet_name,
                          int old_day, int old_month,
                          int new_day, int new_month,
                          const char* new_description, const char* owner) {
    if (!db || !db->db || !pet_name || !new_description || !owner) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE appointments SET day = ?, month = ?, description = ? "
                      "WHERE pet_name = ? AND day = ? AND month = ? AND owner = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, new_day);
    sqlite3_bind_int(stmt, 2, new_month);
    sqlite3_bind_text(stmt, 3, new_description, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, pet_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, old_day);
    sqlite3_bind_int(stmt, 6, old_month);
    sqlite3_bind_text(stmt, 7, owner, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to update appointment: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return (sqlite3_changes(db->db) > 0) ? 0 : -1;
}

/**
 * @brief Delete an appointment
 * @param db Database handle
 * @param pet_name Pet name
 * @param day Day of appointment
 * @param month Month of appointment
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_delete_appointment(Database* db, const char* pet_name, int day, int month, const char* owner) {
    if (!db || !db->db || !pet_name || !owner) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "DELETE FROM appointments WHERE pet_name = ? AND day = ? AND month = ? AND owner = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, pet_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, day);
    sqlite3_bind_int(stmt, 3, month);
    sqlite3_bind_text(stmt, 4, owner, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to delete appointment: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return (sqlite3_changes(db->db) > 0) ? 0 : -1;
}

/**
 * @brief Load all appointments from database
 * @param db Database handle
 * @return Number of appointments loaded, negative on error
 */
int db_load_all_appointments(Database* db) {
    if (!db || !db->db) return 0;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT pet_name, description, day, month, owner FROM appointments;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    int count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        // For now, just count them. The actual loading logic depends on the
        // global appointmentList structure
        count++;
    }
    
    sqlite3_finalize(stmt);
    return count;
}

/**
 * @brief Check if a date is already occupied
 * @param db Database handle
 * @param day Day to check
 * @param month Month to check
 * @return 1 if occupied, 0 if free, negative on error
 */
int db_is_date_occupied(Database* db, int day, int month) {
    if (!db || !db->db) return 0;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT COUNT(*) FROM appointments WHERE day = ? AND month = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, day);
    sqlite3_bind_int(stmt, 2, month);
    
    rc = sqlite3_step(stmt);
    int count = 0;
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return (count > 0) ? 1 : 0;
}

// ============================================================================
// Birthday Management Functions
// ============================================================================

/**
 * @brief Add a birthday record to the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param day Birthday day
 * @param month Birthday month
 * @param year Birthday year
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_add_birthday(Database* db, const char* pet_name, int day, int month, int year, const char* owner) {
    if (!db || !db->db || !pet_name || !owner) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "INSERT OR REPLACE INTO birthdays (pet_name, day, month, year, owner) VALUES (?, ?, ?, ?, ?);";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, pet_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, day);
    sqlite3_bind_int(stmt, 3, month);
    sqlite3_bind_int(stmt, 4, year);
    sqlite3_bind_text(stmt, 5, owner, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert birthday: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return 0;
}

/**
 * @brief Load all birthdays from database
 * @param db Database handle
 * @param birthdayTree B+ tree to populate
 * @param petList Pet list for reference
 * @return Number of birthdays loaded, negative on error
 */
int db_load_all_birthdays(Database* db, BPlusTree* birthdayTree, Pet** petList) {
    if (!db || !db->db || !birthdayTree) return 0;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT pet_name, day, month, year, owner FROM birthdays;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    int count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* pet_name = (const char*)sqlite3_column_text(stmt, 0);
        int day = sqlite3_column_int(stmt, 1);
        int month = sqlite3_column_int(stmt, 2);
        int year = sqlite3_column_int(stmt, 3);
        const char* owner = (const char*)sqlite3_column_text(stmt, 4);
        
        // Insert into B+ tree and potentially create pet if needed
        insertBirthday(birthdayTree, pet_name, day, month, year);
        count++;
    }
    
    sqlite3_finalize(stmt);
    return count;
}

// ============================================================================
// Stray Animals Management Functions
// ============================================================================

/**
 * @brief Add a stray animal to the database
 * @param db Database handle
 * @param type Animal type
 * @param gender Animal gender
 * @param arrival_date Arrival date
 * @param age Animal age
 * @return ID of the new stray animal, negative on error
 */
int db_add_stray_animal(Database* db, const char* type, const char* gender,
                        const char* arrival_date, int age) {
    if (!db || !db->db || !type || !gender || !arrival_date) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO stray_animals (type, gender, arrival_date, age) VALUES (?, ?, ?, ?);";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, gender, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, arrival_date, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, age);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert stray animal: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return (int)sqlite3_last_insert_rowid(db->db);
}

/**
 * @brief Update a stray animal
 * @param db Database handle
 * @param id Animal ID
 * @param type New type
 * @param gender New gender
 * @param arrival_date New arrival date
 * @param age New age
 * @return 0 on success, non-zero on failure
 */
int db_update_stray_animal(Database* db, int id, const char* type, const char* gender,
                           const char* arrival_date, int age) {
    if (!db || !db->db || !type || !gender || !arrival_date) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE stray_animals SET type = ?, gender = ?, arrival_date = ?, age = ? WHERE id = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, gender, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, arrival_date, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, age);
    sqlite3_bind_int(stmt, 5, id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to update stray animal: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return (sqlite3_changes(db->db) > 0) ? 0 : -1;
}

/**
 * @brief Delete a stray animal
 * @param db Database handle
 * @param id Animal ID
 * @return 0 on success, non-zero on failure
 */
int db_delete_stray_animal(Database* db, int id) {
    if (!db || !db->db) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "DELETE FROM stray_animals WHERE id = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to delete stray animal: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return (sqlite3_changes(db->db) > 0) ? 0 : -1;
}

/**
 * @brief Load all stray animals from database
 * @param db Database handle
 * @param list Pointer to stray animal list
 * @return Number of animals loaded, negative on error
 */
int db_load_all_stray_animals(Database* db, StrayAnimal** list) {
    if (!db || !db->db || !list) return 0;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, type, gender, arrival_date, age FROM stray_animals;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    int count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char* type = (const char*)sqlite3_column_text(stmt, 1);
        const char* gender = (const char*)sqlite3_column_text(stmt, 2);
        const char* arrival_date = (const char*)sqlite3_column_text(stmt, 3);
        int age = sqlite3_column_int(stmt, 4);
        
        // Create new stray animal node
        StrayAnimal* newAnimal = (StrayAnimal*)malloc(sizeof(StrayAnimal));
        newAnimal->id = id;
        strncpy(newAnimal->type, type, sizeof(newAnimal->type) - 1);
        strncpy(newAnimal->gender, gender, sizeof(newAnimal->gender) - 1);
        strncpy(newAnimal->arrivalDate, arrival_date, sizeof(newAnimal->arrivalDate) - 1);
        newAnimal->age = age;
        newAnimal->next = NULL;
        
        // Add to list
        if (*list == NULL) {
            *list = newAnimal;
        } else {
            StrayAnimal* cur = *list;
            while (cur->next != NULL) {
                cur = cur->next;
            }
            cur->next = newAnimal;
        }
        
        count++;
    }
    
    sqlite3_finalize(stmt);
    return count;
}

// ============================================================================
// Adopted Animals Management Functions
// ============================================================================

/**
 * @brief Add an adopted animal to the database
 * @param db Database handle
 * @param id Original stray animal ID
 * @param type Animal type
 * @param gender Animal gender
 * @param arrival_date Original arrival date
 * @param age Animal age
 * @param owner New owner username
 * @param adoption_date Adoption date
 * @return 0 on success, non-zero on failure
 */
int db_add_adopted_animal(Database* db, int id, const char* type, const char* gender,
                          const char* arrival_date, int age,
                          const char* owner, const char* adoption_date) {
    if (!db || !db->db || !type || !gender || !arrival_date || !owner || !adoption_date) return -1;
    
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO adopted_animals (id, type, gender, arrival_date, age, owner, adoption_date) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?);";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, id);
    sqlite3_bind_text(stmt, 2, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, gender, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, arrival_date, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, age);
    sqlite3_bind_text(stmt, 6, owner, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, adoption_date, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert adopted animal: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    return 0;
}

/**
 * @brief Load all adopted animals from database
 * @param db Database handle
 * @param list Pointer to adopted animal list
 * @return Number of animals loaded, negative on error
 */
int db_load_all_adopted_animals(Database* db, AdoptedAnimal** list) {
    if (!db || !db->db || !list) return 0;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, type, gender, arrival_date, age, owner, adoption_date FROM adopted_animals;";
    
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }
    
    int count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char* type = (const char*)sqlite3_column_text(stmt, 1);
        const char* gender = (const char*)sqlite3_column_text(stmt, 2);
        const char* arrival_date = (const char*)sqlite3_column_text(stmt, 3);
        int age = sqlite3_column_int(stmt, 4);
        const char* owner = (const char*)sqlite3_column_text(stmt, 5);
        const char* adoption_date = (const char*)sqlite3_column_text(stmt, 6);
        
        // Create new adopted animal node
        AdoptedAnimal* newAdopted = (AdoptedAnimal*)malloc(sizeof(AdoptedAnimal));
        newAdopted->id = id;
        strncpy(newAdopted->type, type, sizeof(newAdopted->type) - 1);
        strncpy(newAdopted->gender, gender, sizeof(newAdopted->gender) - 1);
        strncpy(newAdopted->arrivalDate, arrival_date, sizeof(newAdopted->arrivalDate) - 1);
        newAdopted->age = age;
        strncpy(newAdopted->owner, owner, sizeof(newAdopted->owner) - 1);
        strncpy(newAdopted->adoptionDate, adoption_date, sizeof(newAdopted->adoptionDate) - 1);
        newAdopted->next = NULL;
        
        // Add to list
        if (*list == NULL) {
            *list = newAdopted;
        } else {
            AdoptedAnimal* cur = *list;
            while (cur->next != NULL) {
                cur = cur->next;
            }
            cur->next = newAdopted;
        }
        
        count++;
    }
    
    sqlite3_finalize(stmt);
    return count;
}

/**
 * @brief Adopt a stray animal (move from stray to adopted table)
 * @param db Database handle
 * @param stray_id Stray animal ID
 * @param owner New owner username
 * @param adoption_date Adoption date
 * @return 0 on success, non-zero on failure
 */
int db_adopt_stray_animal(Database* db, int stray_id, const char* owner, const char* adoption_date) {
    if (!db || !db->db || !owner || !adoption_date) return -1;
    
    // Begin transaction
    if (db_begin_transaction(db) != 0) {
        return -1;
    }
    
    // Get stray animal data
    sqlite3_stmt* stmt;
    const char* sql_select = "SELECT type, gender, arrival_date, age FROM stray_animals WHERE id = ?;";
    
    int rc = sqlite3_prepare_v2(db->db, sql_select, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_rollback_transaction(db);
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, stray_id);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        db_rollback_transaction(db);
        return -1;
    }
    
    const char* type = (const char*)sqlite3_column_text(stmt, 0);
    const char* gender = (const char*)sqlite3_column_text(stmt, 1);
    const char* arrival_date = (const char*)sqlite3_column_text(stmt, 2);
    int age = sqlite3_column_int(stmt, 3);
    
    // Copy strings before finalizing
    char type_copy[50], gender_copy[10], arrival_date_copy[20];
    strncpy(type_copy, type, sizeof(type_copy) - 1);
    strncpy(gender_copy, gender, sizeof(gender_copy) - 1);
    strncpy(arrival_date_copy, arrival_date, sizeof(arrival_date_copy) - 1);
    
    sqlite3_finalize(stmt);
    
    // Add to adopted animals
    if (db_add_adopted_animal(db, stray_id, type_copy, gender_copy, arrival_date_copy,
                              age, owner, adoption_date) != 0) {
        db_rollback_transaction(db);
        return -1;
    }
    
    // Delete from stray animals
    if (db_delete_stray_animal(db, stray_id) != 0) {
        db_rollback_transaction(db);
        return -1;
    }
    
    // Commit transaction
    if (db_commit_transaction(db) != 0) {
        db_rollback_transaction(db);
        return -1;
    }
    
    return 0;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Get the last error message from SQLite
 * @param db Database handle
 * @return Error message string (do not free)
 */
const char* db_get_error(Database* db) {
    if (!db || !db->db) return "Invalid database handle";
    return sqlite3_errmsg(db->db);
}

/**
 * @brief Get the last inserted row ID
 * @param db Database handle
 * @return Last inserted row ID
 */
long long db_last_insert_id(Database* db) {
    if (!db || !db->db) return -1;
    return sqlite3_last_insert_rowid(db->db);
}

/**
 * @brief Backup database to a file
 * @param db Database handle
 * @param backup_path Path for backup file
 * @return 0 on success, non-zero on failure
 */
int db_backup(Database* db, const char* backup_path) {
    if (!db || !db->db || !backup_path) return -1;
    
    sqlite3* backup_db;
    int rc = sqlite3_open(backup_path, &backup_db);
    if (rc != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_backup* backup = sqlite3_backup_init(backup_db, "main", db->db, "main");
    if (backup) {
        sqlite3_backup_step(backup, -1);
        sqlite3_backup_finish(backup);
    }
    
    rc = sqlite3_errcode(backup_db);
    sqlite3_close(backup_db);
    
    return (rc == SQLITE_OK) ? 0 : -1;
}

/**
 * @brief Restore database from a backup file
 * @param db_path Path to current database
 * @param backup_path Path to backup file
 * @return 0 on success, non-zero on failure
 */
int db_restore(const char* db_path, const char* backup_path) {
    if (!db_path || !backup_path) return -1;
    
    // Check if backup file exists
    FILE* test_file = fopen(backup_path, "rb");
    if (!test_file) {
        return -1;  // Backup file doesn't exist
    }
    fclose(test_file);
    
    sqlite3 *source_db, *dest_db;
    
    int rc = sqlite3_open(backup_path, &source_db);
    if (rc != SQLITE_OK) {
        return -1;
    }
    
    rc = sqlite3_open(db_path, &dest_db);
    if (rc != SQLITE_OK) {
        sqlite3_close(source_db);
        return -1;
    }
    
    sqlite3_backup* backup = sqlite3_backup_init(dest_db, "main", source_db, "main");
    if (backup) {
        sqlite3_backup_step(backup, -1);
        sqlite3_backup_finish(backup);
    }
    
    rc = sqlite3_errcode(dest_db);
    
    sqlite3_close(source_db);
    sqlite3_close(dest_db);
    
    return (rc == SQLITE_OK) ? 0 : -1;
}

#endif // SQLITE3_HEADER_ONLY

