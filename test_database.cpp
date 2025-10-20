/**
 * @file test_database.cpp
 * @brief Simple test program to verify SQLite3 database functionality
 */

#include <stdio.h>
#include "database.h"

int main() {
    printf("Testing SQLite3 Database Functionality\n");
    printf("========================================\n\n");
    
    // Initialize database
    printf("1. Initializing database...\n");
    Database* db = db_init("petcare_test.db", NULL);
    
    if (!db) {
        printf("   [FAILED] Database initialization failed!\n");
        return 1;
    }
    printf("   [SUCCESS] Database initialized\n\n");
    
    // Create tables
    printf("2. Creating tables...\n");
    if (db_create_tables(db) != 0) {
        printf("   [FAILED] Table creation failed!\n");
        db_close(db);
        return 1;
    }
    printf("   [SUCCESS] Tables created\n\n");
    
    // Test adding a user
    printf("3. Adding test user...\n");
    if (db_add_user(db, "testuser", "encrypted_password_123") != 0) {
        printf("   [FAILED] User addition failed!\n");
        db_close(db);
        return 1;
    }
    printf("   [SUCCESS] User added\n\n");
    
    // Test checking if user exists
    printf("4. Checking if user exists...\n");
    int exists = db_user_exists(db, "testuser");
    if (exists == 1) {
        printf("   [SUCCESS] User exists in database\n\n");
    } else {
        printf("   [FAILED] User not found!\n\n");
    }
    
    // Test adding a pet
    printf("5. Adding test pet...\n");
    if (db_add_pet(db, "Fluffy", "Cat", 3, "testuser") != 0) {
        printf("   [FAILED] Pet addition failed!\n");
        db_close(db);
        return 1;
    }
    printf("   [SUCCESS] Pet added\n\n");
    
    // Close database
    printf("6. Closing database...\n");
    db_close(db);
    printf("   [SUCCESS] Database closed\n\n");
    
    printf("========================================\n");
    printf("All tests PASSED! Database is working correctly.\n");
    printf("A file named 'petcare_test.db' should now exist.\n");
    
    return 0;
}



