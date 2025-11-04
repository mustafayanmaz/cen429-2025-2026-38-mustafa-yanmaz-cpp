/**
 * @file database.h
 * @brief SQLite database wrapper for PetCare application
 */
#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Database handle structure
 */
typedef struct Database {
    sqlite3* db;                /**< SQLite database handle */
    char* db_path;              /**< Path to the database file */
    int is_encrypted;           /**< Flag indicating if DB is encrypted */
    char* temp_path;            /**< Secure mode: decrypted temp path (runtime) */
    int secure_mode;            /**< 1 if DB-at-rest encryption via whitebox is enabled */
} Database;

/**
 * @brief Initialize the database connection
 * @param db_path Path to the database file
 * @param encryption_key Encryption key for the database (can be NULL)
 * @return Pointer to Database handle, NULL on failure
 */
Database* db_init(const char* db_path, const char* encryption_key);

/**
 * @brief Close the database connection
 * @param db Database handle
 */
void db_close(Database* db);

/**
 * @brief Create all necessary tables in the database
 * @param db Database handle
 * @return 0 on success, non-zero on failure
 */
int db_create_tables(Database* db);

/**
 * @brief Execute a SQL query with no result expected
 * @param db Database handle
 * @param sql SQL query string
 * @return 0 on success, non-zero on failure
 */
int db_execute(Database* db, const char* sql);

/**
 * @brief Begin a transaction
 * @param db Database handle
 * @return 0 on success, non-zero on failure
 */
int db_begin_transaction(Database* db);

/**
 * @brief Commit a transaction
 * @param db Database handle
 * @return 0 on success, non-zero on failure
 */
int db_commit_transaction(Database* db);

/**
 * @brief Rollback a transaction
 * @param db Database handle
 * @return 0 on success, non-zero on failure
 */
int db_rollback_transaction(Database* db);

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
int db_add_user(Database* db, const char* username, const char* encrypted_password);

/**
 * @brief Get user's encrypted password from database
 * @param db Database handle
 * @param username Username
 * @param password_out Output buffer for encrypted password (must be freed by caller)
 * @return 0 on success, non-zero on failure
 */
int db_get_user_password(Database* db, const char* username, char** password_out);

/**
 * @brief Check if a user exists
 * @param db Database handle
 * @param username Username
 * @return 1 if exists, 0 if not, negative on error
 */
int db_user_exists(Database* db, const char* username);

/**
 * @brief Load all users from database into a HashTable
 * @param db Database handle
 * @param table HashTable to populate
 * @return Number of users loaded, negative on error
 */
int db_load_all_users(Database* db, struct HashTable* table);

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
int db_add_pet(Database* db, const char* name, const char* type, int age, const char* owner);

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
                  const char* new_name, const char* new_type, int new_age);

/**
 * @brief Delete a pet from the database
 * @param db Database handle
 * @param name Pet name
 * @param owner Owner username (for permission check)
 * @return 0 on success, non-zero on failure
 */
int db_delete_pet(Database* db, const char* name, const char* owner);

/**
 * @brief Load all pets from database into a linked list
 * @param db Database handle
 * @param petList Pointer to pet list head
 * @return Number of pets loaded, negative on error
 */
int db_load_all_pets(Database* db, struct Pet** petList);

/**
 * @brief Check if a pet belongs to a specific owner
 * @param db Database handle
 * @param name Pet name
 * @param owner Owner username
 * @return 1 if owned, 0 if not, negative on error
 */
int db_is_pet_owned_by(Database* db, const char* name, const char* owner);

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
                       int day, int month, const char* owner);

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
                          const char* new_description, const char* owner);

/**
 * @brief Delete an appointment
 * @param db Database handle
 * @param pet_name Pet name
 * @param day Day of appointment
 * @param month Month of appointment
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_delete_appointment(Database* db, const char* pet_name, int day, int month, const char* owner);

/**
 * @brief Load all appointments from database
 * @param db Database handle
 * @return Number of appointments loaded, negative on error
 */
int db_load_all_appointments(Database* db);

/**
 * @brief Check if a date is already occupied
 * @param db Database handle
 * @param day Day to check
 * @param month Month to check
 * @return 1 if occupied, 0 if free, negative on error
 */
int db_is_date_occupied(Database* db, int day, int month);

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
int db_add_birthday(Database* db, const char* pet_name, int day, int month, int year, const char* owner);

/**
 * @brief Load all birthdays from database
 * @param db Database handle
 * @param birthdayTree B+ tree to populate
 * @param petList Pet list for reference
 * @return Number of birthdays loaded, negative on error
 */
int db_load_all_birthdays(Database* db, struct BPlusTree* birthdayTree, struct Pet** petList);

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
                        const char* arrival_date, int age);

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
                           const char* arrival_date, int age);

/**
 * @brief Delete a stray animal
 * @param db Database handle
 * @param id Animal ID
 * @return 0 on success, non-zero on failure
 */
int db_delete_stray_animal(Database* db, int id);

/**
 * @brief Load all stray animals from database
 * @param db Database handle
 * @param list Pointer to stray animal list
 * @return Number of animals loaded, negative on error
 */
int db_load_all_stray_animals(Database* db, struct StrayAnimal** list);

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
                          const char* owner, const char* adoption_date);

/**
 * @brief Load all adopted animals from database
 * @param db Database handle
 * @param list Pointer to adopted animal list
 * @return Number of animals loaded, negative on error
 */
int db_load_all_adopted_animals(Database* db, struct AdoptedAnimal** list);

/**
 * @brief Adopt a stray animal (move from stray to adopted table)
 * @param db Database handle
 * @param stray_id Stray animal ID
 * @param owner New owner username
 * @param adoption_date Adoption date
 * @return 0 on success, non-zero on failure
 */
int db_adopt_stray_animal(Database* db, int stray_id, const char* owner, const char* adoption_date);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Get the last error message from SQLite
 * @param db Database handle
 * @return Error message string (do not free)
 */
const char* db_get_error(Database* db);

/**
 * @brief Get the last inserted row ID
 * @param db Database handle
 * @return Last inserted row ID
 */
long long db_last_insert_id(Database* db);

/**
 * @brief Backup database to a file
 * @param db Database handle
 * @param backup_path Path for backup file
 * @return 0 on success, non-zero on failure
 */
int db_backup(Database* db, const char* backup_path);

/**
 * @brief Restore database from a backup file
 * @param db_path Path to current database
 * @param backup_path Path to backup file
 * @return 0 on success, non-zero on failure
 */
int db_restore(const char* db_path, const char* backup_path);

// ============================================================================
// Feeding Schedule Functions
// ============================================================================

/**
 * @brief Add a feeding schedule to the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param schedule_details Schedule details
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_add_feeding_schedule(Database* db, const char* pet_name, const char* schedule_details, const char* owner);

/**
 * @brief Update a feeding schedule in the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param owner Owner username
 * @param new_details New schedule details
 * @return 0 on success, non-zero on failure
 */
int db_update_feeding_schedule(Database* db, const char* pet_name, const char* owner, const char* new_details);

/**
 * @brief Delete a feeding schedule from the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_delete_feeding_schedule(Database* db, const char* pet_name, const char* owner);

// ============================================================================
// Medicine Schedule Functions
// ============================================================================

/**
 * @brief Add a medicine schedule to the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param schedule_details Schedule details
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_add_medicine_schedule(Database* db, const char* pet_name, const char* schedule_details, const char* owner);

/**
 * @brief Update a medicine schedule in the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param owner Owner username
 * @param new_details New schedule details
 * @return 0 on success, non-zero on failure
 */
int db_update_medicine_schedule(Database* db, const char* pet_name, const char* owner, const char* new_details);

/**
 * @brief Delete a medicine schedule from the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_delete_medicine_schedule(Database* db, const char* pet_name, const char* owner);

// ============================================================================
// Exercise Routine Functions
// ============================================================================

/**
 * @brief Add an exercise routine to the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param exercise_details Exercise details
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_add_exercise_routine(Database* db, const char* pet_name, const char* exercise_details, const char* owner);

/**
 * @brief Update an exercise routine in the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param owner Owner username
 * @param new_details New exercise details
 * @return 0 on success, non-zero on failure
 */
int db_update_exercise_routine(Database* db, const char* pet_name, const char* owner, const char* new_details);

/**
 * @brief Delete an exercise routine from the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_delete_exercise_routine(Database* db, const char* pet_name, const char* owner);

// Loaders from DB into memory structures
int db_load_feeding_schedules(Database* db, struct Queue* queue);
int db_load_medicine_schedules(Database* db, struct Queue* queue);
int db_load_exercise_routines(Database* db, const char* owner);

// ============================================================================
// Grooming Routine Functions
// ============================================================================

/**
 * @brief Add a grooming routine to the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param grooming_details Grooming details
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_add_grooming_routine(Database* db, const char* pet_name, const char* grooming_details, const char* owner);

/**
 * @brief Update a grooming routine in the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param owner Owner username
 * @param new_details New grooming details
 * @return 0 on success, non-zero on failure
 */
int db_update_grooming_routine(Database* db, const char* pet_name, const char* owner, const char* new_details);

/**
 * @brief Delete a grooming routine from the database
 * @param db Database handle
 * @param pet_name Pet name
 * @param owner Owner username
 * @return 0 on success, non-zero on failure
 */
int db_delete_grooming_routine(Database* db, const char* pet_name, const char* owner);

/**
 * @brief Print all grooming routines to stdout
 */
int db_print_all_groomings(Database* db);

#ifdef __cplusplus
}
#endif

#endif /* DATABASE_H */

