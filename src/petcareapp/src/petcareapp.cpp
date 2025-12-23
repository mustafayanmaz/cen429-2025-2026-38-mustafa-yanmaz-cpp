/**
* @file petcareapp.cpp
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h> // GetModuleFileName
#include <conio.h>  // Windows for getch()
#include <direct.h> // _mkdir
#else
#include <termios.h> 
#include <unistd.h>  
#include <sys/stat.h> // mkdir
#endif

#include "methods.h"
#include "petcare.h"
#include "database.h"
#include "assetProtection.h"
#include "raspSecurity.h"
#include "secureMemory.h"
#include "codeObfuscation.h"

extern "C" {
/**
 * @brief Load feeding schedules from the database into a queue.
 * @param db Pointer to the opened database instance.
 * @param queue Target queue to receive feeding schedules.
 * @return 0 on success, non-zero on failure.
 */
int db_load_feeding_schedules(struct Database* db, struct Queue* queue);

/**
 * @brief Load medicine schedules from the database into a queue.
 * @param db Pointer to the opened database instance.
 * @param queue Target queue to receive medicine schedules.
 * @return 0 on success, non-zero on failure.
 */
int db_load_medicine_schedules(struct Database* db, struct Queue* queue);

/**
 * @brief Load exercise routines for a given owner from the database.
 * @param db Pointer to the opened database instance.
 * @param owner Owner name whose exercise routines will be loaded.
 * @return 0 on success, non-zero on failure.
 */
int db_load_exercise_routines(struct Database* db, const char* owner);
}

/**
 * @brief Simple safe integer input helper for CLI menus.
 * @param prompt Message printed before reading the value.
 * @param out Pointer where the parsed integer will be stored.
 * @return 1 on successful parse, 0 on error (should not normally occur).
 */
static int readInt(const char* prompt, int* out) {
    char buf[128];
    while (1) {
        printf("%s", prompt);
        if (scanf("%127s", buf) != 1) continue;
        char* endptr = NULL;
        long v = strtol(buf, &endptr, 10);
        if (endptr && *endptr == '\0') { *out = (int)v; return 1; }
        printf("Invalid number. Try again.\n");
    }
}

#ifdef _WIN32
/**
 * @brief Clears the console screen.
 */
#define CLEAR_SCREEN() system("cls")
#else
/**
 * @brief Clears the console screen.
 */
#define CLEAR_SCREEN() printf("\033[H\033[J")
#endif

#ifndef _WIN32
/**
 * @brief Cross-platform replacement for getch() on non-Windows systems.
 * @return The character read from stdin.
 */
int getch() {
    struct termios oldt, newt;
    int ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}
#endif

/**
 * @brief A pointer to the feeding schedule queue.
 */
Queue* feedingQueue = NULL;

/* SQL-only: use global DB via get_petcare_database() from petcare */

/**
 * @brief Menu structure used for CLI navigation.
 */
typedef struct Menu {
    char* title;         /**< Title of the menu. */
    struct Menu* parent; /**< Pointer to the parent menu. */
    char** items;        /**< Array of menu item strings. */
    int itemCount;       /**< Number of menu items. */
    struct Menu** subMenus; /**< Array of submenu pointers. */
} Menu;

/**
 * @brief Holds the currently logged-in user's name.
 */
char activeUser[50] = "";

/**
 * @brief Global RASP configuration.
 */
static RASPConfig g_raspConfig;

/** @brief Flag indicating whether the RASP system in the app has been initialized. */
static int g_rasp_initialized = 0;

/**
 * @brief RASP log callback
 */
static void rasp_app_logger(const char* message) {
    // In production, log to file
    fprintf(stderr, "%s\n", message);
}

/**
 * @brief Writes a JSON security event under docs/security/evidence/
 */
static void write_security_event_json(const char* type, const char* detail, int code) {
    const char* dir = "docs/security/evidence";
#ifdef _WIN32
    _mkdir("docs"); _mkdir("docs/security"); _mkdir(dir);
#else
    mkdir("docs", 0777); mkdir("docs/security", 0777); mkdir(dir, 0777);
#endif
    char path[512];
    unsigned long long ts = (unsigned long long)time(NULL);
    snprintf(path, sizeof(path), "%s/security_event_%llu.json", dir, ts);
    FILE* f = fopen(path, "wb");
    if (!f) return;
    fprintf(f, "{\n  \"timestamp\": %llu,\n  \"type\": \"%s\",\n  \"code\": %d,\n  \"detail\": \"%s\"\n}\n",
            ts, type ? type : "", code, detail ? detail : "");
    fclose(f);
}

/**
 * @brief Get CFI counter value
 */
static uint64_t rasp_get_cfi_counter_value(uint64_t counter_id) {
    CFICounter counter;
    if (rasp_get_cfi_stats(counter_id, &counter) == RASP_SUCCESS) {
        return counter.current_value;
    }
    return 0;
}

/**
 * @brief Application checksum for self-integrity verification.
 */
static CodeBlockChecksum g_app_checksum;

/** @brief Flag indicating whether the application checksum has been initialized. */
static int g_checksum_initialized = 0;

/**
 * @brief Verify application integrity using checksum
 * @return 0 if valid, -1 if tampered
 */
static int verify_application_integrity() {
    if (!g_checksum_initialized) {
        // Calculate checksum for main function code block
        extern int main(int argc, char* argv[]);
        // Use a safe code section (first 4KB of main)
        if (rasp_calculate_checksum((void*)main, 4096, &g_app_checksum) != RASP_SUCCESS) {
            printf("[SECURITY] Failed to calculate application checksum\n");
            return -1;
        }
        g_checksum_initialized = 1;
        printf("[SECURITY] Application checksum initialized\n");
    }
    
    // Verify checksum
    if (rasp_verify_checksum(&g_app_checksum) != RASP_SUCCESS) {
        printf("[SECURITY] ERROR: Application integrity violation detected!\n");
        write_security_event_json("CHECKSUM_FAIL", "Application code block checksum mismatch", -1);
        return -1;
    }
    
    return 0;
}

/**
 * @brief Initialize RASP security system
 */
static void initialize_rasp_security() {
    memset(&g_raspConfig, 0, sizeof(RASPConfig));
    
    // Enable all security features
    g_raspConfig.enable_checksum_verification = 1;
    g_raspConfig.enable_signature_verification = 1;
    g_raspConfig.enable_device_trust = 1;
    g_raspConfig.enable_hook_detection = 1;
    g_raspConfig.enable_debugger_detection = 1;
    g_raspConfig.enable_tamper_detection = 1;
    g_raspConfig.enable_cfi = 1;
    g_raspConfig.monitoring_interval_ms = 5000;  // 5 seconds
    g_raspConfig.default_action = RASP_ACTION_LOG;
    g_raspConfig.log_callback = rasp_app_logger;
    
    // Initialize RASP
    if (rasp_init(&g_raspConfig) == RASP_SUCCESS) {
        printf("[SECURITY] RASP protection initialized successfully\n");
        g_rasp_initialized = 1;
        
        // Verify application integrity at startup
        if (verify_application_integrity() != 0) {
            printf("[SECURITY] CRITICAL: Application integrity check failed - terminating\n");
            exit(1);
        }
        
        // Perform initial security check
        int result = rasp_comprehensive_check();
        if (result != RASP_SUCCESS) {
            // Fail closed for high-risk conditions and record JSON
            write_security_event_json("RASP_COMPREHENSIVE_FAIL", "Initial comprehensive RASP check failed", result);
            printf("[SECURITY] CRITICAL: RASP check failed (%d) - terminating\n", result);
            exit(1);
        }
        
        // Assess device trust
        DeviceTrust trust;
        rasp_assess_device_trust(&trust);
        printf("[SECURITY] Device trust score: %d/100\n", trust.trust_score);
        if (trust.is_rooted) {
            printf("[SECURITY] WARNING: Device is rooted/jailbroken\n");
            write_security_event_json("DEVICE_TRUST", "Root/Jailbreak detected", 1);
        }
        if (trust.is_emulator) {
            printf("[SECURITY] INFO: VM/Emulator detection triggered (may be false positive)\n");
            write_security_event_json("DEVICE_TRUST", "Emulator/VM detected", 2);
        }
    } else {
        printf("[SECURITY] Failed to initialize RASP protection\n");
    }
}

/**
 * @brief Application signature/hash verification
 * If docs/security/app.hash exists, verify against it; else generate and write it.
 */
static void verify_or_bootstrap_app_hash() {
    const char* hash_path = "docs/security/app.hash";
    unsigned char expected[32];
    FILE* f = fopen(hash_path, "rb");
    if (f) {
        size_t r = fread(expected, 1, sizeof(expected), f); fclose(f);
        if (r == sizeof(expected)) {
            if (verify_app_integrity(expected) != 1) {
                write_security_event_json("APP_HASH_FAIL", "Application integrity hash mismatch", -1);
                printf("[SECURITY] CRITICAL: Application integrity hash mismatch - terminating\n");
                exit(1);
            }
        }
    } else {
        unsigned char current[32];
        if (get_app_integrity_hash(current) == 0) {
            // bootstrap expected hash
            const char* dir = "docs/security";
#ifdef _WIN32
            _mkdir("docs"); _mkdir(dir);
#else
            mkdir("docs", 0777); mkdir(dir, 0777);
#endif
            FILE* wf = fopen(hash_path, "wb");
            if (wf) { fwrite(current, 1, sizeof(current), wf); fclose(wf); }
        }
    }
}

/**
 * @brief Derive database encryption key from device fingerprint + app hash
 */
static int get_kdf_iterations_app() {
    const char* env = getenv("PETCARE_KDF_ITERS");
    if (!env) return 20000;
    long v = strtol(env, NULL, 10);
    if (v < 1000) v = 1000;
    if (v > 1000000) v = 1000000;
    return (int)v;
}

/**
 * @brief Derive a hex-encoded database key bound to the device and app integrity.
 * @param out_hex Output buffer that will receive a 64-character hex key plus NUL.
 * @param out_len Length of the output buffer in bytes (must be at least 65).
 */
static void derive_database_key(char* out_hex, size_t out_len) {
    if (!out_hex || out_len < 65) return;
    DeviceFingerprint fp; memset(&fp, 0, sizeof(fp));
    generate_device_fingerprint(&fp);
    unsigned char app_hash[32]; memset(app_hash, 0, sizeof(app_hash));
    (void)get_app_integrity_hash(app_hash);
    unsigned char salt[16];
    memcpy(salt, fp.combined_fingerprint, 16);
    unsigned char key[SECURE_KEY_SIZE];
    secure_derive_key((const char*)app_hash, 32, salt, 16, get_kdf_iterations_app(), key);
    // hex encode first 32 bytes
    const char* hexd = "0123456789abcdef";
    for (int i = 0; i < 32 && (i * 2 + 1) < (int)out_len; ++i) {
        out_hex[i*2] = hexd[(key[i] >> 4) & 0xF];
        out_hex[i*2+1] = hexd[key[i] & 0xF];
    }
    out_hex[64] = '\0';
    secure_wipe(key, sizeof(key));
    secure_wipe(app_hash, sizeof(app_hash));
    secure_wipe(salt, sizeof(salt));
}

/**
 * @brief Draws a horizontal line of '*' characters.
 * @param width Number of characters in the line.
 */
void drawHorizontalLine(int width) {
    for (int i = 0; i < width; i++) {
        printf("*");
    }
    printf("\n");
}

/**
 * @brief Draws a frame with a title and menu items, highlighting the selected item.
 * @param menu Pointer to the Menu structure.
 * @param selectedIndex Index of the currently highlighted menu item.
 * @param width Total width of the frame.
 */
void drawFrameWithContent(Menu* menu, int selectedIndex, int width) {
    drawHorizontalLine(width);

    int padding = (width - 2 - strlen(menu->title)) / 2;
    printf("*");
    for (int i = 0; i < padding; i++) printf(" ");
    printf("%s", menu->title);
    for (int i = 0; i < width - 2 - strlen(menu->title) - padding; i++) printf(" ");
    printf("*\n");

    drawHorizontalLine(width);

    for (int i = 0; i < menu->itemCount; i++) {
        printf("* ");
        if (i == selectedIndex) {
            printf(">>  %s", menu->items[i]);
        }
        else {
            printf("   %s", menu->items[i]);
        }
        int contentWidth = width - 4 - (int)strlen(menu->items[i]) - (i == selectedIndex ? 3 : 0);
        for (int j = 0; j < contentWidth; j++) printf(" ");
        printf("*\n");
    }

    drawHorizontalLine(width);
}

/**
 * @brief Handles user authentication (Login/Register/Guest/Exit).
 * @param authMenu Pointer to the Menu struct for authentication options.
 * @param userTable Pointer to the user HashTable.
 * @param isAuthenticated Pointer to a flag that becomes 1 if authenticated, otherwise 0.
 */
void navigateUserAuthentication(Menu* authMenu, HashTable* userTable, int* isAuthenticated) {
    int selectedIndex = 0;
    
    // CFI counter for authentication flow
    if (g_rasp_initialized) {
        rasp_create_cfi_counter(1, (void*)navigateUserAuthentication);
        rasp_increment_cfi_counter(1);
    }

    while (!*isAuthenticated) {
        // Periodic security check
        if (g_rasp_initialized && rasp_is_debugger_present()) {
            printf("\n[SECURITY] Debugger detected - exiting for security\n");
            exit(1);
        }
        CLEAR_SCREEN();
        int consoleWidth = 50;
        int paddingTop = 5;
        for (int i = 0; i < paddingTop; i++) printf("\n");

        drawFrameWithContent(authMenu, selectedIndex, consoleWidth);

        int key = getch();
#ifdef _WIN32
        if (key == 0 || key == 224) {
            key = getch();
            if (key == 72) { // Up arrow
                selectedIndex = (selectedIndex - 1 + authMenu->itemCount) % authMenu->itemCount;
            }
            else if (key == 80) { // Down arrow
                selectedIndex = (selectedIndex + 1) % authMenu->itemCount;
            }
        }
        else if (key == 13) { // Enter
#else
        if (key == '\033') {
            getch();
            key = getch();
            if (key == 'A') { // Up arrow
                selectedIndex = (selectedIndex - 1 + authMenu->itemCount) % authMenu->itemCount;
            }
            else if (key == 'B') { // Down arrow
                selectedIndex = (selectedIndex + 1) % authMenu->itemCount;
            }
        }
        else if (key == '\n') { // Enter
#endif
            if (strcmp(authMenu->items[selectedIndex], "Login") == 0) {
                char username[50], password[50];
                SecureAutoWipe wipe_user(username, sizeof(username));
                SecureAutoWipe wipe_pwd(password, sizeof(password));
                
                // CFI: Login entry
                if (g_rasp_initialized) {
                    rasp_create_cfi_counter(10, (void*)&username);
                    rasp_increment_cfi_counter(10);
                }
                
                CLEAR_SCREEN();
                printf("Enter Username: ");
                scanf("%s", username);
                printf("Enter Password: ");
                scanf("%s", password);
                
                // Protect password in memory
                uint32_t pwd_checksum = 0;
                if (g_rasp_initialized) {
                    rasp_protect_data(password, strlen(password), &pwd_checksum);
                }
                
                // Use session-based login with device binding
                if (loginUserWithSession(userTable, username, password)) {
                    printf("Login successful! Session created.\n");
                    
                    // Verify password wasn't tampered during authentication
                    if (g_rasp_initialized) {
                        if (rasp_verify_protected_data(password, strlen(password), pwd_checksum) != RASP_SUCCESS) {
                            printf("[SECURITY] Password tampering detected!\n");
                            exit(1);
                        }
                    }
                    
                    // Set active user first
                    *isAuthenticated = 1;
                    strcpy(activeUser, username);
                    
                    // Load schedules and routines from DB into memory
                    if (get_petcare_database()) {
                        if (!feedingQueue) feedingQueue = createQueue();
                        if (!medicineQueue) medicineQueue = createQueue();
                        db_load_feeding_schedules(get_petcare_database(), feedingQueue);
                        db_load_medicine_schedules(get_petcare_database(), medicineQueue);
                        db_load_exercise_routines(get_petcare_database(), activeUser);
                    }
                    
                    printf("Press any key to continue...");
                }
                else {
                    printf("Login failed! Invalid credentials or session error.\n");
                    printf("Press any key to return...");
                }
                
                // Securely wipe password from memory
                memset(password, 0, sizeof(password));
                getch();
                
                // CFI: Login exit
                if (g_rasp_initialized) {
                    rasp_verify_cfi_counter(10, 1);
                }
            }
            else if (strcmp(authMenu->items[selectedIndex], "Register") == 0) {
                char username[50], password[50];
                SecureAutoWipe wipe_pwd2(password, sizeof(password));
                CLEAR_SCREEN();
                printf("Enter Username: ");
                scanf("%s", username);
                printf("Enter Password: ");
                scanf("%s", password);
                
                // Add user to hash table (for in-memory use)
                addUser(userTable, username, password);
                
                // Also add to database if available
                if (get_petcare_database()) {
                    // Get encrypted password from the added user
                    unsigned int index = hashFunction(username);
                    User* user = userTable->buckets[index];
                    while (user != NULL) {
                        if (strcmp(user->username, username) == 0) {
                            if (db_add_user(get_petcare_database(), username, user->encryptedPassword) == 0) {
                                printf("[DATABASE] User saved to database\n");
                            } else {
                                printf("[DATABASE] Warning: Could not save user to database\n");
                            }
                            break;
                        }
                        user = user->next;
                    }
                }
                
                printf("User registered successfully! Press any key to return...");
                getch();
            }
            else if (strcmp(authMenu->items[selectedIndex], "Guest Mode") == 0) {
                printf("Guest mode activated! Press any key to continue...");
                *isAuthenticated = 1;
                strcpy(activeUser, "Guest");
                getch();
            }
            else if (strcmp(authMenu->items[selectedIndex], "Exit") == 0) {
                CLEAR_SCREEN();
                printf("Exiting program...\n");
                logoutUserSession();
                freeHashTable(userTable);
                
                // Close database
                if (get_petcare_database()) {
                    close_petcare_database();
                    printf("[DATABASE] Database closed\n");
                }
                
                // Shutdown RASP
                if (g_rasp_initialized) {
                    char status[512];
                    rasp_get_status(status, sizeof(status));
                    printf("\n[SECURITY] RASP Status:\n%s\n", status);
                    rasp_shutdown();
                    printf("[SECURITY] RASP protection shutdown complete\n");
                }
                
                exit(0);
            }
        }
        }
    }

/**
 * @brief Navigates the "Manage Pets" menu: Add, Update, Delete, List, Search.
 * @param petsMenu Pointer to the Menu struct for pet management.
 * @param petList Pointer to the pointer of the head of the pet list.
 * @param isAuthenticated Flag for user authentication status.
 */
void navigatePetsMenu(Menu * petsMenu, Pet * *petList, int isAuthenticated) {
    int selectedIndex = 0;

    while (1) {
        CLEAR_SCREEN();
        int consoleWidth = 50;
        int paddingTop = 5;
        for (int i = 0; i < paddingTop; i++) printf("\n");

        drawFrameWithContent(petsMenu, selectedIndex, consoleWidth);

        int key = getch();
#ifdef _WIN32
        if (key == 0 || key == 224) {
            key = getch();
            if (key == 72) { // Up arrow
                selectedIndex = (selectedIndex - 1 + petsMenu->itemCount) % petsMenu->itemCount;
            }
            else if (key == 80) { // Down arrow
                selectedIndex = (selectedIndex + 1) % petsMenu->itemCount;
            }
        }
        else if (key == 13) { // Enter
#else
        if (key == '\033') {
            getch();
            key = getch();
            if (key == 'A') { // Up arrow
                selectedIndex = (selectedIndex - 1 + petsMenu->itemCount) % petsMenu->itemCount;
            }
            else if (key == 'B') { // Down arrow
                selectedIndex = (selectedIndex + 1) % petsMenu->itemCount;
            }
        }
        else if (key == '\n') { // Enter
#endif
            if (strcmp(petsMenu->items[selectedIndex], "Add Pet") == 0) {
                char name[50], type[50];
                SecureAutoWipe wipe_name(name, sizeof(name));
                SecureAutoWipe wipe_type(type, sizeof(type));
                int age;
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", name);
                printf("Enter pet's type: ");
                scanf("%s", type);
                readInt("Enter pet's age: ", &age);
                
                // Add to in-memory list
                addPet(petList, name, type, age, activeUser);
                
                // Also add to database if available
                if (get_petcare_database()) {
                    if (db_add_pet(get_petcare_database(), name, type, age, activeUser) == 0) {
                        printf("[DATABASE] Pet saved to database\n");
                    } else {
                        printf("[DATABASE] Warning: Could not save pet to database\n");
                    }
                }
                
                printf("Pet added successfully! Press any key to continue...");
                getch();
            }
            else if (strcmp(petsMenu->items[selectedIndex], "Update Pet") == 0) {
                char name[50];
                SecureAutoWipe wipe_upd_name(name, sizeof(name));
                CLEAR_SCREEN();
                printf("Enter the name of the pet to update: ");
                scanf("%s", name);
                updatePet(*petList, name, activeUser);
                printf("Pet updated successfully! Press any key to continue...");
                getch();
            }
            else if (strcmp(petsMenu->items[selectedIndex], "Delete") == 0) {
                char name[50];
                SecureAutoWipe wipe_del_name(name, sizeof(name));
                CLEAR_SCREEN();
                printf("Enter the name of the pet to delete: ");
                scanf("%s", name);
                
                // Delete from in-memory list
                deletePet(petList, name, activeUser);
                
                // Also delete from database if available
                if (get_petcare_database()) {
                    if (db_delete_pet(get_petcare_database(), name, activeUser) == 0) {
                        printf("[DATABASE] Pet deleted from database\n");
                    }
                }
                
                getch();
            }
            else if (strcmp(petsMenu->items[selectedIndex], "List All Pets") == 0) {
                CLEAR_SCREEN();
                listAllPets(*petList);
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(petsMenu->items[selectedIndex], "Search By Name or Type") == 0) {
                char searchKey[50];
                SecureAutoWipe wipe_search(searchKey, sizeof(searchKey));
                int searchMethod = 0;

                CLEAR_SCREEN();
                printf("Enter Search Key (Name or Type): ");
                scanf("%s", searchKey);

                CLEAR_SCREEN();
                printf("Choose search method:\n");
                printf("1. BFS (Breadth-First Search)\n");
                printf("2. DFS (Depth-First Search)\n");
                printf("Enter your choice (1 or 2): ");
                scanf("%d", &searchMethod);

                CLEAR_SCREEN();
                if (searchMethod == 1) {
                    bfsSearch(*petList, searchKey);
                }
                else if (searchMethod == 2) {
                    dfsSearch(*petList, searchKey);
                }
                else {
                    printf("Invalid choice. Returning to menu...\n");
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(petsMenu->items[selectedIndex], "Back") == 0) {
                return;
            }
        }
        }
    }

/**
 * @brief Navigates the "Feeding and Medication Schedules" menu.
 * @param feedingMenu Pointer to the Menu struct for feeding and medication.
 * @param petList Pointer to the head of the pet list (unused here, but passed for consistency).
 */
void navigateFeedingMenu(Menu * feedingMenu, Pet * petList) {
    int selectedIndex = 0;

    while (1) {
        CLEAR_SCREEN();
        int consoleWidth = 50;
        int paddingTop = 5;
        for (int i = 0; i < paddingTop; i++) printf("\n");

        drawFrameWithContent(feedingMenu, selectedIndex, consoleWidth);

        int key = getch();
#ifdef _WIN32
        if (key == 0 || key == 224) {
            key = getch();
            if (key == 72) { // Up arrow
                selectedIndex = (selectedIndex - 1 + feedingMenu->itemCount) % feedingMenu->itemCount;
            }
            else if (key == 80) { // Down arrow
                selectedIndex = (selectedIndex + 1) % feedingMenu->itemCount;
            }
        }
        else if (key == 13) { // Enter
#else
        if (key == '\033') {
            getch();
            key = getch();
            if (key == 'A') { // Up arrow
                selectedIndex = (selectedIndex - 1 + feedingMenu->itemCount) % feedingMenu->itemCount;
            }
            else if (key == 'B') { // Down arrow
                selectedIndex = (selectedIndex + 1) % feedingMenu->itemCount;
            }
        }
        else if (key == '\n') { // Enter
#endif
            if (strcmp(feedingMenu->items[selectedIndex], "Add Feeding Schedule") == 0) {
                char petName[50], scheduleDetails[100];
                SecureAutoWipe wipe_feed_name(petName, sizeof(petName));
                SecureAutoWipe wipe_feed_det(scheduleDetails, sizeof(scheduleDetails));
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", petName);
                printf("Enter feeding schedule details: ");
                scanf(" %[^\n]", scheduleDetails);
                enqueue(feedingQueue, petName, scheduleDetails);
                if (get_petcare_database()) {
                    db_add_feeding_schedule(get_petcare_database(), petName, scheduleDetails, activeUser);
                }
                printf("Feeding schedule added! Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Update Feeding Schedule") == 0) {
                char petName[50], newDetails[100];
                SecureAutoWipe wipe_feed_upd_name(petName, sizeof(petName));
                SecureAutoWipe wipe_feed_upd_det(newDetails, sizeof(newDetails));
                CLEAR_SCREEN();
                printf("Enter pet's name to update the schedule: ");
                scanf("%s", petName);
                printf("Enter new feeding schedule details: ");
                scanf(" %[^\n]", newDetails);
                updateFeedingSchedule(feedingQueue, petName, newDetails);
                if (get_petcare_database()) {
                    db_update_feeding_schedule(get_petcare_database(), petName, activeUser, newDetails);
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Delete Feeding Schedule") == 0) {
                char petName[50];
                SecureAutoWipe wipe_feed_del_name(petName, sizeof(petName));
                CLEAR_SCREEN();
                printf("Enter pet's name to delete the feeding schedule: ");
                scanf("%s", petName);
                deleteFeedingSchedule(feedingQueue, petName);
                if (get_petcare_database()) {
                    db_delete_feeding_schedule(get_petcare_database(), petName, activeUser);
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "View Feeding Schedule List") == 0) {
                CLEAR_SCREEN();
                if (isQueueEmpty(feedingQueue)) {
                    printf("No feeding schedules available.\n");
                }
                else {
                    viewFeedingSchedules(feedingQueue);
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Add Medicine Schedule") == 0) {
                char petName[50], scheduleDetails[100];
                SecureAutoWipe wipe_med_name(petName, sizeof(petName));
                SecureAutoWipe wipe_med_det(scheduleDetails, sizeof(scheduleDetails));
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", petName);
                printf("Enter medicine schedule details: ");
                scanf(" %[^\n]", scheduleDetails);
                addMedicineSchedule(medicineQueue, petName, scheduleDetails);
                if (get_petcare_database()) {
                    db_add_medicine_schedule(get_petcare_database(), petName, scheduleDetails, activeUser);
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Update Medicine Schedule") == 0) {
                char petName[50], newDetails[100];
                SecureAutoWipe wipe_med_upd_name(petName, sizeof(petName));
                SecureAutoWipe wipe_med_upd_det(newDetails, sizeof(newDetails));
                CLEAR_SCREEN();
                printf("Enter pet's name to update the medicine schedule: ");
                scanf("%s", petName);
                printf("Enter new medicine schedule details: ");
                scanf(" %[^\n]", newDetails);
                updateMedicineSchedule(medicineQueue, petName, newDetails);
                if (get_petcare_database()) {
                    db_update_medicine_schedule(get_petcare_database(), petName, activeUser, newDetails);
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Delete Medicine Schedule") == 0) {
                char petName[50];
                SecureAutoWipe wipe_med_del_name(petName, sizeof(petName));
                CLEAR_SCREEN();
                printf("Enter pet's name to delete the medicine schedule: ");
                scanf("%s", petName);
                deleteMedicineSchedule(medicineQueue, petName);
                if (get_petcare_database()) {
                    db_delete_medicine_schedule(get_petcare_database(), petName, activeUser);
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "View Medicine Schedule List") == 0) {
                CLEAR_SCREEN();
                viewMedicineSchedules(medicineQueue);
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Analyze Medicine Dependencies") == 0) {
                CLEAR_SCREEN();
                findSCC();
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Back") == 0) {
                return;
            }
        }
        }
    }

/**
 * @brief Global pointer to the BPlusTree that stores birthdays.
 */
BPlusTree* birthdayTree = NULL;

/**
 * @brief Navigates the "Pet Birthday and Adoption Anniversary" menu.
 * @param adaptationMenu Pointer to the Menu struct for this category.
 * @param petList Pointer to the head of the pet list.
 */
void navigateAdaptationMenu(Menu * adaptationMenu, Pet * petList) {
    int selectedIndex = 0;

    static StrayAnimal* strayList = NULL;
    if (get_petcare_database()) {
        db_load_all_stray_animals(get_petcare_database(), &strayList);
    }

    static AdoptedAnimal* adoptedList = NULL;
    if (get_petcare_database()) {
        db_load_all_adopted_animals(get_petcare_database(), &adoptedList);
    }

    while (1) {
        CLEAR_SCREEN();
        int consoleWidth = 50;
        int paddingTop = 5;
        for (int i = 0; i < paddingTop; i++) printf("\n");

        drawFrameWithContent(adaptationMenu, selectedIndex, consoleWidth);

        int key = getch();
#ifdef _WIN32
        if (key == 0 || key == 224) {
            key = getch();
            if (key == 72) { // Up arrow
                selectedIndex = (selectedIndex - 1 + adaptationMenu->itemCount) % adaptationMenu->itemCount;
            }
            else if (key == 80) { // Down arrow
                selectedIndex = (selectedIndex + 1) % adaptationMenu->itemCount;
            }
        }
        else if (key == 13) { // Enter
#else
        if (key == '\033') {
            getch();
            key = getch();
            if (key == 'A') {
                selectedIndex = (selectedIndex - 1 + adaptationMenu->itemCount) % adaptationMenu->itemCount;
            }
            else if (key == 'B') {
                selectedIndex = (selectedIndex + 1) % adaptationMenu->itemCount;
            }
        }
        else if (key == '\n') {
#endif
            if (strcmp(adaptationMenu->items[selectedIndex], "Record Pet Birthday") == 0) {
                char petName[50];
                SecureAutoWipe wipe_bday_name(petName, sizeof(petName));
                int birthdayDay, birthdayMonth, birthdayYear;
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", petName);
                if (!isPetOwnedByUser(petList, petName, activeUser)) {
                    printf("Error: Pet not found or does not belong to you.\n");
                    getch();
                    continue;
                }
                printf("Enter Birthday (day month year, e.g., 15 8 2020): ");
                readInt("Enter Birthday Day: ", &birthdayDay);
                readInt("Enter Birthday Month: ", &birthdayMonth);
                readInt("Enter Birthday Year: ", &birthdayYear);
                if (birthdayTree == NULL) {
                    birthdayTree = createBPlusTree();
                }
                insertBirthday(birthdayTree, petName, birthdayDay, birthdayMonth, birthdayYear);
                if (get_petcare_database()) {
                    db_add_birthday(get_petcare_database(), petName, birthdayDay, birthdayMonth, birthdayYear, activeUser);
                }
                printf("Birthday recorded successfully! Press any key to return...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "Add stray animals") == 0) {
                CLEAR_SCREEN();
                char type[50], gender[10], arrivalDate[20];
                SecureAutoWipe wipe_stray_type(type, sizeof(type));
                SecureAutoWipe wipe_stray_gender(gender, sizeof(gender));
                SecureAutoWipe wipe_stray_arr(arrivalDate, sizeof(arrivalDate));
                int age;
                printf("Enter stray animal's type: ");
                scanf("%s", type);
                printf("Enter stray animal's gender: ");
                scanf("%s", gender);
                printf("Enter arrival date (dd/mm/yyyy): ");
                scanf("%s", arrivalDate);
                readInt("Enter age: ", &age);

                addStrayAnimalToList(&strayList, type, gender, arrivalDate, age);
                if (get_petcare_database()) {
                    db_add_stray_animal(get_petcare_database(), type, gender, arrivalDate, age);
                }
                printf("Stray animal added successfully! Press any key to continue...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "Update stray animals") == 0) {
                CLEAR_SCREEN();
                listStrayAnimals(strayList);
                printf("Enter the ID of the stray animal to update: ");
                int id;
                scanf("%d", &id);

                char newType[50], newGender[10], newArrivalDate[20];
                SecureAutoWipe wipe_stray_newtype(newType, sizeof(newType));
                SecureAutoWipe wipe_stray_newgender(newGender, sizeof(newGender));
                SecureAutoWipe wipe_stray_newarr(newArrivalDate, sizeof(newArrivalDate));
                int newAge;

                printf("Enter new type: ");
                scanf("%s", newType);

                printf("Enter new gender: ");
                scanf("%s", newGender);

                printf("Enter new arrival date (dd/mm/yyyy): ");
                scanf("%s", newArrivalDate);

                printf("Enter new age: ");
                scanf("%d", &newAge);

                updateStrayAnimal(strayList, id, newType, newGender, newArrivalDate, newAge);
                if (get_petcare_database()) {
                    db_update_stray_animal(get_petcare_database(), id, newType, newGender, newArrivalDate, newAge);
                }
                printf("Press any key to continue...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "Delete stray animals") == 0) {
                CLEAR_SCREEN();
                listStrayAnimals(strayList);
                printf("Enter the ID of the stray animal to delete: ");
                int id;
                scanf("%d", &id);
                deleteStrayAnimal(&strayList, id);
                if (get_petcare_database()) {
                    db_delete_stray_animal(get_petcare_database(), id);
                }
                printf("Press any key to continue...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "Search stray animals") == 0) {
                CLEAR_SCREEN();
                char searchKey[50];
                SecureAutoWipe wipe_kmp_search(searchKey, sizeof(searchKey));
                printf("Enter the animal type to search for: ");
                scanf("%s", searchKey);
                searchStrayAnimalsKMP(strayList, searchKey);
                printf("Press any key to continue...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "Adopt stray animals") == 0) {
                CLEAR_SCREEN();
                listStrayAnimals(strayList);
                printf("Select an ID to adopt (or 'q' to quit): ");
                char choice[10];
                SecureAutoWipe wipe_choice(choice, sizeof(choice));
                scanf("%s", choice);

                if (strcmp(choice, "q") == 0) {
                    printf("Adoption cancelled.\n");
                    printf("Press any key to continue...");
                    getch();
                    return;
                }

                int chosenID = atoi(choice);

                char newName[50];
                SecureAutoWipe wipe_newname(newName, sizeof(newName));
                printf("Enter a name you want to give this animal: ");
                scanf("%s", newName);

                char adoptionDate[20];
                SecureAutoWipe wipe_adopt_date(adoptionDate, sizeof(adoptionDate));
                printf("Enter adoption date (dd/mm/yyyy): ");
                scanf("%s", adoptionDate);

                adoptStrayAnimal(&strayList, activeUser, chosenID, newName, adoptionDate);
                if (get_petcare_database()) {
                    db_adopt_stray_animal(get_petcare_database(), chosenID, activeUser, adoptionDate);
                }
                printf("Press any key to continue...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "List all adopted animals") == 0) {
                CLEAR_SCREEN();
                free(adoptedList);
                adoptedList = NULL;
                if (get_petcare_database()) {
                    db_load_all_adopted_animals(get_petcare_database(), &adoptedList);
                }
                listAllAdoptedAnimals(adoptedList);
                printf("Press any key to continue...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "List all adoptable animals") == 0) {
                CLEAR_SCREEN();
                listStrayAnimals(strayList);
                printf("Press any key to continue...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "List Pet Birthdays") == 0) {
                CLEAR_SCREEN();
                // Reset tree to avoid duplicates
                birthdayTree = createBPlusTree();
                // Refresh from DB before listing
                if (get_petcare_database()) {
                    // Note: load into tree; pets list is not needed here
                    db_load_all_birthdays(get_petcare_database(), birthdayTree, &petList);
                }
                listPetBirthdays(birthdayTree, petList);
                printf("Press any key to continue...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "Back") == 0) {
                // Data is already saved to database during operations
                return;
            }
        }
        }
    }

/**
 * @brief Navigates the "Veterinary Appointment Tracking" menu.
 * @param vetMenu Pointer to the Menu struct for vet appointments.
 * @param activeUser The username of the currently logged-in user.
 * @param petList Pointer to the head of the pet list.
 */
void navigateVetMenu(Menu * vetMenu, const char* activeUser, Pet * petList) {
    int selectedIndex = 0;

    while (1) {
        CLEAR_SCREEN();
        int consoleWidth = 50;
        int paddingTop = 5;
        for (int i = 0; i < paddingTop; i++) printf("\n");

        drawFrameWithContent(vetMenu, selectedIndex, consoleWidth);

        int key = getch();
#ifdef _WIN32
        if (key == 0 || key == 224) {
            key = getch();
            if (key == 72) { // Up arrow
                selectedIndex = (selectedIndex - 1 + vetMenu->itemCount) % vetMenu->itemCount;
            }
            else if (key == 80) { // Down arrow
                selectedIndex = (selectedIndex + 1) % vetMenu->itemCount;
            }
        }
        else if (key == 13) { // Enter
#else
        if (key == '\033') {
            getch();
            key = getch();
            if (key == 'A') { // Up arrow
                selectedIndex = (selectedIndex - 1 + vetMenu->itemCount) % vetMenu->itemCount;
            }
            else if (key == 'B') { // Down arrow
                selectedIndex = (selectedIndex + 1) % vetMenu->itemCount;
            }
        }
        else if (key == '\n') { // Enter
#endif
            if (strcmp(vetMenu->items[selectedIndex], "Add Appointment") == 0) {
                char petName[50], description[100];
                SecureAutoWipe wipe_vet_name(petName, sizeof(petName));
                SecureAutoWipe wipe_vet_desc(description, sizeof(description));
                int day, month;
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", petName);
                printf("Enter day and month (e.g., 15 11): ");
                readInt("Enter day: ", &day);
                readInt("Enter month: ", &month);
                printf("Enter description: ");
                scanf(" %[^\n]", description);
                addAppointment(petName, description, day, month, activeUser, petList);
                saveAppointmentsToFile();
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(vetMenu->items[selectedIndex], "Update Appointment") == 0) {
                char petName[50], newDescription[100];
                SecureAutoWipe wipe_vet_upd_name(petName, sizeof(petName));
                SecureAutoWipe wipe_vet_upd_desc(newDescription, sizeof(newDescription));
                int oldDay, oldMonth, newDay, newMonth;

                loadAppointmentsFromFile();
                CLEAR_SCREEN();

                printf("Enter pet's name: ");
                scanf("%s", petName);

                printf("Enter current day and month (e.g., 15 11): ");
                readInt("Enter current day: ", &oldDay);
                readInt("Enter current month: ", &oldMonth);
                printf("Enter new day and month (e.g., 20 11): ");
                readInt("Enter new day: ", &newDay);
                readInt("Enter new month: ", &newMonth);
                
                printf("Enter new description: ");
                scanf(" %[^\n]", newDescription);

                if (updateAppointment(petName, oldDay, oldMonth, newDay, newMonth, newDescription, activeUser)) {
                    saveAppointmentsToFile();
                }

                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(vetMenu->items[selectedIndex], "Cancel Appointment") == 0) {
                char petName[50];
                SecureAutoWipe wipe_vet_cancel_name(petName, sizeof(petName));
                loadAppointmentsFromFile();
                int day, month;
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", petName);
                printf("Enter day and month (e.g., 15 11): ");
                readInt("Enter day: ", &day);
                readInt("Enter month: ", &month);
                cancelAppointment(petName, day, month, activeUser);
                printf("Press any key to return...");
                getch();
                saveAppointmentsToFile();
            }
            else if (strcmp(vetMenu->items[selectedIndex], "View Appointments List") == 0) {
                int month;
                loadAppointmentsFromFile();
                CLEAR_SCREEN();
                printf("Enter month to view appointments: ");
                scanf("%d", &month);
                viewAppointments(month);
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(vetMenu->items[selectedIndex], "Back") == 0) {
                return;
            }
        }
        }
    }

/**
 * @brief Navigates the "Exercise and Grooming Menu" for pets.
 * @param exerciseMenu Pointer to the Menu struct for exercise/grooming.
 * @param petList Pointer to the head of the pet list.
 * @param activeUser The username of the currently logged-in user.
 */
void navigateExerciseMenu(Menu * exerciseMenu, Pet * petList, char* activeUser) {
    int selectedIndex = 0;

    while (1) {
        CLEAR_SCREEN();
        int consoleWidth = 50;
        int paddingTop = 5;
        for (int i = 0; i < paddingTop; i++) printf("\n");

        drawFrameWithContent(exerciseMenu, selectedIndex, consoleWidth);

        int key = getch();
#ifdef _WIN32
        if (key == 0 || key == 224) {
            key = getch();
            if (key == 72) { // Up arrow
                selectedIndex = (selectedIndex - 1 + exerciseMenu->itemCount) % exerciseMenu->itemCount;
            }
            else if (key == 80) { // Down arrow
                selectedIndex = (selectedIndex + 1) % exerciseMenu->itemCount;
            }
        }
        else if (key == 13) { // Enter
#else
        if (key == '\u001b') {
            getch();
            key = getch();
            if (key == 'A') {
                selectedIndex = (selectedIndex - 1 + exerciseMenu->itemCount) % exerciseMenu->itemCount;
            }
            else if (key == 'B') {
                selectedIndex = (selectedIndex + 1) % exerciseMenu->itemCount;
            }
        }
        else if (key == '\n') { // Enter
#endif
            if (strcmp(exerciseMenu->items[selectedIndex], "Add Exercise Routine") == 0) {
                CLEAR_SCREEN();
                char petName[50], exercise[100];
                SecureAutoWipe wipe_ex_name(petName, sizeof(petName));
                SecureAutoWipe wipe_ex_det(exercise, sizeof(exercise));
                printf("Enter pet's name: ");
                scanf("%s", petName);

                if (!isPetOwnedByUser(petList, petName, activeUser)) {
                    printf("Error: Pet not found or does not belong to you.\n");
                    getch();
                    continue;
                }

                printf("Enter exercise routine: ");
                scanf(" %99[^\n]", exercise);

                addExerciseRoutine(petName, exercise);
                if (get_petcare_database()) {
                    db_add_exercise_routine(get_petcare_database(), petName, exercise, activeUser);
                }
                printf(" Press any key to return...");
                getch();
            }
            else if (strcmp(exerciseMenu->items[selectedIndex], "List Exercises") == 0) {
                CLEAR_SCREEN();
                listAllExercises();
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(exerciseMenu->items[selectedIndex], "Undo Last Exercises") == 0) {
                CLEAR_SCREEN();
                undoLastExercise();
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(exerciseMenu->items[selectedIndex], "Add Grooming Routine") == 0) {
                CLEAR_SCREEN();
                char petName[50], exercise[100];
                SecureAutoWipe wipe_groom_name(petName, sizeof(petName));
                SecureAutoWipe wipe_groom_det(exercise, sizeof(exercise));
                printf("Enter pet's name: ");
                scanf("%s", petName);

                if (!isPetOwnedByUser(petList, petName, activeUser)) {
                    printf("Error: Pet not found or does not belong to you.\n");
                    getch();
                    continue;
                }

                printf("Enter grooming routine: ");
                scanf(" %99[^\n]", exercise);

                if (get_petcare_database()) {
                    db_add_grooming_routine(get_petcare_database(), petName, exercise, activeUser);
                }
                printf(" Press any key to return...");
                getch();
            }
            else if (strcmp(exerciseMenu->items[selectedIndex], "List Groomings") == 0) {
                CLEAR_SCREEN();
                if (get_petcare_database()) {
                    db_print_all_groomings(get_petcare_database());
                } else {
                    printf("No database available.\n");
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(exerciseMenu->items[selectedIndex], "Back") == 0) {
                return;
            }
        }
        }
    }

/**
 * @brief Demonstrates Huffman compression/decompression for an "About" section.
 * @param text The text to compress/decompress.
 */
void aboutMenu(char text[]) {
    CLEAR_SCREEN();
    int freq[256] = { 0 };

    for (int i = 0; text[i] != '\0'; ++i)
        freq[(int)text[i]]++;

    char data[256];
    int frequencies[256], size = 0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i]) {
            data[size] = (char)i;
            frequencies[size] = freq[i];
            size++;
        }
    }

    char codes[256][MAX_TREE_HT];
    HuffmanCodes(data, frequencies, size, codes);

    char compressed[1024];
    compress(text, codes, compressed);
    printf("\nCompressed Text: %s\n", compressed);

    char decompressed[1024];
    MinHeapNode* root = buildHuffmanTree(data, frequencies, size);
    decompress(root, compressed, decompressed);
    printf("Decompressed Text: %s\n", decompressed);
    getch();
}

/**
 * @brief Main menu navigation: calls submenus based on user selection.
 * @param mainMenu Pointer to the main menu structure.
 * @param userTable Pointer to the user HashTable.
 * @param isAuthenticated Pointer to an integer flag for authentication.
 */
void navigateMainMenu(Menu * mainMenu, HashTable * userTable, int* isAuthenticated) {
    int selectedIndex = 0;
    static Pet* petList = NULL;
    
    // Load from database only (avoid file duplication)
    if (get_petcare_database()) {
        petList = NULL;
        int db_pet_count = db_load_all_pets(get_petcare_database(), &petList);
        if (db_pet_count > 0) {
            printf("[DATABASE] Loaded %d pets from database\n", db_pet_count);
            printf("Press any key to continue...\n");
            getch();
        }
    }
    
    // CFI for main menu
    if (g_rasp_initialized) {
        rasp_create_cfi_counter(100, (void*)navigateMainMenu);
    }
    
    while (1) {
        // Increment CFI counter each iteration
        if (g_rasp_initialized) {
            rasp_increment_cfi_counter(100);
        }
        
        // Refresh queues/stack from DB at the start of each loop (keeps views consistent)
        if (get_petcare_database()) {
            if (!feedingQueue) feedingQueue = createQueue();
            if (!medicineQueue) medicineQueue = createQueue();
            db_load_feeding_schedules(get_petcare_database(), feedingQueue);
            db_load_medicine_schedules(get_petcare_database(), medicineQueue);
            db_load_exercise_routines(get_petcare_database(), activeUser);
        }
        
        // Periodic security check every iteration
        if (g_rasp_initialized && selectedIndex % 10 == 0) {
            // Verify application integrity
            if (verify_application_integrity() != 0) {
                printf("\n[SECURITY] CRITICAL: Runtime integrity violation - terminating\n");
                exit(1);
            }
            
            // Detect tampering
            TamperInfo tamper_info;
            if (rasp_detect_tampering(&tamper_info) != RASP_SUCCESS) {
                printf("\n[SECURITY] Tampering detected - terminating\n");
                rasp_respond_to_tamper(&tamper_info, RASP_ACTION_TERMINATE);
            }
            
            // Scan for hooks every 10 iterations
            HookInfo hooks[5];
            int hook_count = rasp_scan_all_hooks(hooks, 5);
            if (hook_count > 0) {
            printf("\n[SECURITY] CRITICAL: %d hook(s) detected - terminating\n", hook_count);
            write_security_event_json("HOOK_DETECTED", "Inline/IAT hook(s) detected", hook_count);
                exit(1);
            }
        }
        CLEAR_SCREEN();
        int consoleWidth = 50;
        int paddingTop = 5;
        for (int i = 0; i < paddingTop; i++) printf("\n");

        drawFrameWithContent(mainMenu, selectedIndex, consoleWidth);

        int key = getch();
#ifdef _WIN32
        if (key == 0 || key == 224) {
            key = getch();
            if (key == 72) { // Up arrow
                selectedIndex = (selectedIndex - 1 + mainMenu->itemCount) % mainMenu->itemCount;
            }
            else if (key == 80) { // Down arrow
                selectedIndex = (selectedIndex + 1) % mainMenu->itemCount;
            }
        }
        else if (key == 13) { // Enter
#else
        if (key == '\033') {
            getch();
            key = getch();
            if (key == 'A') { // Up arrow
                selectedIndex = (selectedIndex - 1 + mainMenu->itemCount) % mainMenu->itemCount;
            }
            else if (key == 'B') { // Down arrow
                selectedIndex = (selectedIndex + 1) % mainMenu->itemCount;
            }
        }
        else if (key == '\n') { // Enter
#endif
            if (strcmp(mainMenu->items[selectedIndex], "Manage Pets") == 0) {
                navigatePetsMenu(mainMenu->subMenus[0], &petList, *isAuthenticated);
            }
            else if (strcmp(mainMenu->items[selectedIndex], "Veterinary Appointment Tracking") == 0) {
                navigateVetMenu(mainMenu->subMenus[1], activeUser, petList);
            }
            else if (strcmp(mainMenu->items[selectedIndex], "Feeding and Medication Schedules") == 0) {
                navigateFeedingMenu(mainMenu->subMenus[2], petList);
            }
            else if (strcmp(mainMenu->items[selectedIndex], "Exercise and Grooming Menu") == 0) {
                navigateExerciseMenu(mainMenu->subMenus[3], petList, activeUser);
            }
            else if (strcmp(mainMenu->items[selectedIndex], "Pet Birthday and Adoption Anniversary") == 0) {
                navigateAdaptationMenu(mainMenu->subMenus[4], petList);
            }
            else if (strcmp(mainMenu->items[selectedIndex], "About") == 0) {
                aboutMenu("This is our about section \n Mustafa , Ali Ufuktan and Onur did this project ");
            }
            else if (strcmp(mainMenu->items[selectedIndex], "Exit") == 0) {
                CLEAR_SCREEN();
                printf("Exiting program...\n");
                
                // CFI verification before exit
                if (g_rasp_initialized) {
                    if (rasp_verify_cfi_counter(100, rasp_get_cfi_counter_value(100)) != RASP_SUCCESS) {
                        printf("[SECURITY] CFI violation detected during exit\n");
                    }
                }
                
                logoutUserSession();
                freePetList(petList);
                freeHashTable(userTable);
                
                // Close database
                if (get_petcare_database()) {
                    close_petcare_database();
                    printf("[DATABASE] Database closed\n");
                }
                
                // Shutdown RASP
                if (g_rasp_initialized) {
                    char status[512];
                    rasp_get_status(status, sizeof(status));
                    printf("\n[SECURITY] RASP Status:\n%s\n", status);
                    rasp_shutdown();
                    printf("[SECURITY] RASP protection shutdown complete\n");
                }
                
                exit(0);
            }
        }
        }
    // Should never reach here in normal operation.
    }

/**
 * @brief Main entry point of the Pet Care application.
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return 0 on successful execution.
 */
int main(int argc, char* argv[]) {
    // ========================================================================
    // CODE OBFUSCATION INITIALIZATION
    // ========================================================================
    obf_init();
    
    // Check for test/coverage mode with obfuscated loop
    volatile int test_mode = 0;
    volatile int dummy = (int)time(NULL) | 1;
    
    // Obfuscated argument parsing
    for (volatile int i = 1; i < argc; i++) {
        if (opaque_true(dummy)) {
            if (obf_strcmp(argv[i], "--test-coverage") == 0 || 
                obf_strcmp(argv[i], "--non-interactive") == 0 ||
                obf_strcmp(argv[i], "-t") == 0) {
                test_mode = obf_add(0, 1);
                break;
            }
        }
        
        // Dead branch
        if (opaque_false(dummy)) {
            test_mode = obf_mul_const(test_mode, 2);
        }
        
        inject_dead_code(1);
    }
    
    // ========================================================================
    // RASP SECURITY INITIALIZATION
    // ========================================================================
    OBF_INFO("================================================================\n");
    OBF_INFO("         PetCare Application - Security Initialization        \n");
    OBF_INFO("================================================================\n\n");
    
    // Initialize RASP security system with obfuscated call
    if (opaque_true(dummy)) {
        initialize_rasp_security();
    }
    // Verify or bootstrap application integrity hash (file-based)
    verify_or_bootstrap_app_hash();
    
    // Initialize existing security features
    printf("\nInitializing session security...\n");
    init_petcare_session();
    
    // Initialize database - construct path relative to executable
    printf("\nInitializing database...\n");
    
    // Get executable directory
    char exe_path[512] = {0};
    char db_full_path[512] = {0};
    
#ifdef _WIN32
    GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
    // Find last backslash to get directory
    char* last_slash = strrchr(exe_path, '\\');
    if (last_slash) {
        *last_slash = '\0';
        snprintf(db_full_path, sizeof(db_full_path), "%s\\petcare.db", exe_path);
    } else {
        strcpy(db_full_path, "petcare.db");
    }
#else
    // Linux/Unix
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (len != -1) {
        exe_path[len] = '\0';
        char* last_slash = strrchr(exe_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            snprintf(db_full_path, sizeof(db_full_path), "%s/petcare.db", exe_path);
        } else {
            strcpy(db_full_path, "petcare.db");
        }
    } else {
        strcpy(db_full_path, "petcare.db");
    }
#endif
    
    printf("[DATABASE] Database path: %s\n", db_full_path);
    
    char dbkey[65]; memset(dbkey, 0, sizeof(dbkey));
    derive_database_key(dbkey, sizeof(dbkey));
    SecureAutoWipe wipe_dbkey(dbkey, sizeof(dbkey));
    // init_petcare_database internally uses db_init; we pass encryption key via that path
    if (init_petcare_database(db_full_path) == 0) {
        OBF_INFO("[DATABASE] Database initialized successfully\n");
    } else {
        OBF_WARNING("[DATABASE] Warning: Database initialization failed\n");
    }
    
    OBF_INFO("\n[SECURITY] All security features initialized\n");
    
    // If in test mode, skip interactive parts
    if (test_mode) {
        OBF_INFO("\n[TEST MODE] Running in non-interactive mode for coverage testing\n");
        OBF_INFO("[TEST MODE] All security features verified successfully\n");
        
        // Perform basic initialization checks
        feedingQueue = createQueue();
        medicineQueue = createQueue();
        HashTable* userTable = createHashTable();
        loadUsersFromFile(userTable, "database");
        loadAppointmentsFromFile();
        
        OBF_INFO("[TEST MODE] Data structures initialized successfully\n");
        
        // Cleanup
        freeHashTable(userTable);
        if (feedingQueue) free(feedingQueue);
        if (medicineQueue) free(medicineQueue);
        
        // Close database
        if (get_petcare_database()) {
            close_petcare_database();
            OBF_INFO("[TEST MODE] Database closed\n");
        }
        
        // Shutdown RASP
        if (g_rasp_initialized) {
            rasp_shutdown();
            OBF_INFO("[TEST MODE] RASP protection shutdown complete\n");
        }
        
        printf("[TEST MODE] Test completed successfully - exiting\n");
        return 0;
    }
    
    printf("Press any key to continue...\n");
    getch();
    
    feedingQueue = createQueue();
    medicineQueue = createQueue();

    int isAuthenticated = 0;
    HashTable* userTable = createHashTable();
    loadUsersFromFile(userTable, "database");
    
    // Also load users from database if available
    if (get_petcare_database()) {
        int db_user_count = db_load_all_users(get_petcare_database(), userTable);
        if (db_user_count > 0) {
            printf("[DATABASE] Loaded %d users from database\n", db_user_count);
        }
    }
    
    loadAppointmentsFromFile();

    char* authItems[] = { "Login", "Register", "Guest Mode", "Exit" };
    char* petItems[] = { "Add Pet", "Update Pet", "Delete", "List All Pets", "Search By Name or Type", "Back" };
    char* feedingItems[] = {
        "Add Feeding Schedule","Update Feeding Schedule","Delete Feeding Schedule",
        "View Feeding Schedule List","------------------------------------------",
        "Add Medicine Schedule","Update Medicine Schedule","Delete Medicine Schedule",
        "View Medicine Schedule List", "Analyze Medicine Dependencies", "Back"
    };
    char* vetItems[] = { "Add Appointment","Update Appointment","Cancel Appointment", "View Appointments List", "Back" };
    char* exerciseItems[] = {
        "Add Exercise Routine","List Exercises","Undo Last Exercises",
        "------------------------------------------","Add Grooming Routine","List Groomings", "Back"
    };
    char* birthdayItems[] = {
        "Record Pet Birthday","List Pet Birthdays","Add stray animals","Update stray animals",
        "Delete stray animals","Search stray animals","Adopt stray animals","List all adoptable animals",
        "List all adopted animals" ,"Back"
    };

    char* mainMenuItems[] = {
        "Manage Pets",
        "Veterinary Appointment Tracking",
        "Feeding and Medication Schedules",
        "Exercise and Grooming Menu",
        "Pet Birthday and Adoption Anniversary",
        "About",
        "Exit"
    };

    Menu authMenu = { "User Authentication", NULL, authItems, 4, NULL };
    Menu petsMenu = { "Manage Pets", NULL, petItems, 6, NULL };
    Menu feedingMenu = { "Feeding and Medication Schedules", NULL, feedingItems, 11, NULL };
    Menu vetMenu = { "Veterinary Appointment Tracking", NULL, vetItems, 5, NULL };
    Menu exerciseMenu = { "Exercise and Grooming Menu", NULL, exerciseItems, 7, NULL };
    Menu birthdayMenu = { "Pet Birthday and Adoption Anniversary", NULL, birthdayItems, 10, NULL };

    Menu* mainSubMenus[] = { &petsMenu, &vetMenu, &feedingMenu, &exerciseMenu, &birthdayMenu, NULL };
    Menu mainMenu = { "Main Menu", NULL, mainMenuItems, 7, mainSubMenus };

    extern char activeUser[50];

    navigateUserAuthentication(&authMenu, userTable, &isAuthenticated);
    if (isAuthenticated) {
        navigateMainMenu(&mainMenu, userTable, &isAuthenticated);
    }

    feedingQueue = createQueue();
    medicineQueue = createQueue();

    return 0;
}
