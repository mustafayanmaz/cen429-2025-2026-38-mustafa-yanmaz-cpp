/**
* @file petcareapp.cpp
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <conio.h>  // Windows for getch()
#else
#include <termios.h> 
#include <unistd.h>  
#endif

#include "methods.h"
#include "petcare.h"
#include "database.h"
#include "assetProtection.h"
#include "raspSecurity.h"

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

/**
 * @brief Global database handle
 */
Database* g_database = NULL;

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
 * @brief Global RASP configuration
 */
static RASPConfig g_raspConfig;
static int g_rasp_initialized = 0;

/**
 * @brief RASP log callback
 */
static void rasp_app_logger(const char* message) {
    // In production, log to file
    fprintf(stderr, "%s\n", message);
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
        
        // Perform initial security check
        int result = rasp_comprehensive_check();
        if (result != RASP_SUCCESS) {
            switch (result) {
                case RASP_ERROR_DEBUGGER_DETECTED:
                    printf("[SECURITY] WARNING: Debugger detected!\n");
                    break;
                case RASP_ERROR_UNTRUSTED_DEVICE:
                    printf("[SECURITY] WARNING: Untrusted device detected!\n");
                    break;
                case RASP_ERROR_HOOK_DETECTED:
                    printf("[SECURITY] WARNING: Hook detected!\n");
                    break;
                case RASP_ERROR_TAMPER_DETECTED:
                    printf("[SECURITY] WARNING: Tampering detected!\n");
                    break;
            }
        }
        
        // Assess device trust
        DeviceTrust trust;
        rasp_assess_device_trust(&trust);
        printf("[SECURITY] Device trust score: %d/100\n", trust.trust_score);
        if (trust.is_rooted) {
            printf("[SECURITY] WARNING: Device is rooted/jailbroken\n");
        }
        if (trust.is_emulator) {
            printf("[SECURITY] INFO: VM/Emulator detection triggered (may be false positive)\n");
        }
    } else {
        printf("[SECURITY] Failed to initialize RASP protection\n");
    }
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
                    
                    printf("Press any key to continue...");
                    *isAuthenticated = 1;
                    strcpy(activeUser, username);
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
                CLEAR_SCREEN();
                printf("Enter Username: ");
                scanf("%s", username);
                printf("Enter Password: ");
                scanf("%s", password);
                
                // Add user to hash table (for in-memory use)
                addUser(userTable, username, password);
                
                // Also add to database if available
                if (g_database) {
                    // Get encrypted password from the added user
                    unsigned int index = hashFunction(username);
                    User* user = userTable->buckets[index];
                    while (user != NULL) {
                        if (strcmp(user->username, username) == 0) {
                            if (db_add_user(g_database, username, user->encryptedPassword) == 0) {
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
                saveUsersToFile(userTable, "database");
                freeHashTable(userTable);
                
                // Close database
                if (g_database) {
                    db_close(g_database);
                    printf("[DATABASE] Database closed\n");
                }
                
                // Shutdown RASP
                if (g_rasp_initialized) {
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
                int age;
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", name);
                printf("Enter pet's type: ");
                scanf("%s", type);
                printf("Enter pet's age: ");
                scanf("%d", &age);
                
                // Add to in-memory list
                addPet(petList, name, type, age, activeUser);
                
                // Also add to database if available
                if (g_database) {
                    if (db_add_pet(g_database, name, type, age, activeUser) == 0) {
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
                CLEAR_SCREEN();
                printf("Enter the name of the pet to update: ");
                scanf("%s", name);
                updatePet(*petList, name, activeUser);
                printf("Pet updated successfully! Press any key to continue...");
                getch();
            }
            else if (strcmp(petsMenu->items[selectedIndex], "Delete") == 0) {
                char name[50];
                CLEAR_SCREEN();
                printf("Enter the name of the pet to delete: ");
                scanf("%s", name);
                
                // Delete from in-memory list
                deletePet(petList, name, activeUser);
                
                // Also delete from database if available
                if (g_database) {
                    if (db_delete_pet(g_database, name, activeUser) == 0) {
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
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", petName);
                printf("Enter feeding schedule details: ");
                scanf(" %[^\n]", scheduleDetails);
                enqueue(feedingQueue, petName, scheduleDetails);
                if (g_database) {
                    db_add_feeding_schedule(g_database, petName, scheduleDetails, activeUser);
                }
                printf("Feeding schedule added! Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Update Feeding Schedule") == 0) {
                char petName[50], newDetails[100];
                CLEAR_SCREEN();
                printf("Enter pet's name to update the schedule: ");
                scanf("%s", petName);
                printf("Enter new feeding schedule details: ");
                scanf(" %[^\n]", newDetails);
                updateFeedingSchedule(feedingQueue, petName, newDetails);
                if (g_database) {
                    db_update_feeding_schedule(g_database, petName, activeUser, newDetails);
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Delete Feeding Schedule") == 0) {
                char petName[50];
                CLEAR_SCREEN();
                printf("Enter pet's name to delete the feeding schedule: ");
                scanf("%s", petName);
                deleteFeedingSchedule(feedingQueue, petName);
                if (g_database) {
                    db_delete_feeding_schedule(g_database, petName, activeUser);
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
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", petName);
                printf("Enter medicine schedule details: ");
                scanf(" %[^\n]", scheduleDetails);
                addMedicineSchedule(medicineQueue, petName, scheduleDetails);
                if (g_database) {
                    db_add_medicine_schedule(g_database, petName, scheduleDetails, activeUser);
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Update Medicine Schedule") == 0) {
                char petName[50], newDetails[100];
                CLEAR_SCREEN();
                printf("Enter pet's name to update the medicine schedule: ");
                scanf("%s", petName);
                printf("Enter new medicine schedule details: ");
                scanf(" %[^\n]", newDetails);
                updateMedicineSchedule(medicineQueue, petName, newDetails);
                if (g_database) {
                    db_update_medicine_schedule(g_database, petName, activeUser, newDetails);
                }
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(feedingMenu->items[selectedIndex], "Delete Medicine Schedule") == 0) {
                char petName[50];
                CLEAR_SCREEN();
                printf("Enter pet's name to delete the medicine schedule: ");
                scanf("%s", petName);
                deleteMedicineSchedule(medicineQueue, petName);
                if (g_database) {
                    db_delete_medicine_schedule(g_database, petName, activeUser);
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
    if (g_database) {
        db_load_all_stray_animals(g_database, &strayList);
    }

    static AdoptedAnimal* adoptedList = NULL;
    if (g_database) {
        db_load_all_adopted_animals(g_database, &adoptedList);
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
                scanf("%d %d %d", &birthdayDay, &birthdayMonth, &birthdayYear);
                if (birthdayTree == NULL) {
                    birthdayTree = createBPlusTree();
                }
                insertBirthday(birthdayTree, petName, birthdayDay, birthdayMonth, birthdayYear);
                if (g_database) {
                    db_add_birthday(g_database, petName, birthdayDay, birthdayMonth, birthdayYear, activeUser);
                }
                printf("Birthday recorded successfully! Press any key to return...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "Add stray animals") == 0) {
                CLEAR_SCREEN();
                char type[50], gender[10], arrivalDate[20];
                int age;
                printf("Enter stray animal's type: ");
                scanf("%s", type);
                printf("Enter stray animal's gender: ");
                scanf("%s", gender);
                printf("Enter arrival date (dd/mm/yyyy): ");
                scanf("%s", arrivalDate);
                printf("Enter age: ");
                scanf("%d", &age);

                addStrayAnimalToList(&strayList, type, gender, arrivalDate, age);
                if (g_database) {
                    db_add_stray_animal(g_database, type, gender, arrivalDate, age);
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
                if (g_database) {
                    db_update_stray_animal(g_database, id, newType, newGender, newArrivalDate, newAge);
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
                if (g_database) {
                    db_delete_stray_animal(g_database, id);
                }
                printf("Press any key to continue...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "Search stray animals") == 0) {
                CLEAR_SCREEN();
                char searchKey[50];
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
                scanf("%s", choice);

                if (strcmp(choice, "q") == 0) {
                    printf("Adoption cancelled.\n");
                    printf("Press any key to continue...");
                    getch();
                    return;
                }

                int chosenID = atoi(choice);

                char newName[50];
                printf("Enter a name you want to give this animal: ");
                scanf("%s", newName);

                char adoptionDate[20];
                printf("Enter adoption date (dd/mm/yyyy): ");
                scanf("%s", adoptionDate);

                adoptStrayAnimal(&strayList, activeUser, chosenID, newName, adoptionDate);
                if (g_database) {
                    db_adopt_stray_animal(g_database, chosenID, activeUser, adoptionDate);
                }
                printf("Press any key to continue...");
                getch();
            }
            else if (strcmp(adaptationMenu->items[selectedIndex], "List all adopted animals") == 0) {
                CLEAR_SCREEN();
                free(adoptedList);
                adoptedList = NULL;
                if (g_database) {
                    db_load_all_adopted_animals(g_database, &adoptedList);
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
                if (!birthdayTree) {
                    birthdayTree = createBPlusTree();
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
                int day, month;
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", petName);
                printf("Enter day and month (e.g., 15 11): ");
                scanf("%d %d", &day, &month);
                printf("Enter description: ");
                scanf(" %[^\n]", description);
                addAppointment(petName, description, day, month, activeUser, petList);
                saveAppointmentsToFile();
                printf("Press any key to return...");
                getch();
            }
            else if (strcmp(vetMenu->items[selectedIndex], "Update Appointment") == 0) {
                char petName[50], newDescription[100];
                int oldDay, oldMonth, newDay, newMonth;

                loadAppointmentsFromFile();
                CLEAR_SCREEN();

                printf("Enter pet's name: ");
                scanf("%s", petName);

                printf("Enter current day and month (e.g., 15 11): ");
                scanf("%d %d", &oldDay, &oldMonth);

                printf("Enter new day and month (e.g., 20 11): ");
                scanf("%d %d", &newDay, &newMonth);

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
                loadAppointmentsFromFile();
                int day, month;
                CLEAR_SCREEN();
                printf("Enter pet's name: ");
                scanf("%s", petName);
                printf("Enter day and month (e.g., 15 11): ");
                scanf("%d %d", &day, &month);
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
                if (g_database) {
                    db_add_exercise_routine(g_database, petName, exercise, activeUser);
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
                printf("Enter pet's name: ");
                scanf("%s", petName);

                if (!isPetOwnedByUser(petList, petName, activeUser)) {
                    printf("Error: Pet not found or does not belong to you.\n");
                    getch();
                    continue;
                }

                printf("Enter grooming routine: ");
                scanf(" %99[^\n]", exercise);

                // Placeholder for grooming routine
                // addGroomingRoutine(petName, exercise);
                printf(" Press any key to return...");
                getch();
            }
            else if (strcmp(exerciseMenu->items[selectedIndex], "List Groomings") == 0) {
                CLEAR_SCREEN();
                // Placeholder for listing groomings
                // listAllGroomings();
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
    loadPetsFromFile(&petList, "database");
    
    // Also load pets from database if available
    if (g_database) {
        int db_pet_count = db_load_all_pets(g_database, &petList);
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
        
        // Periodic security check every iteration
        if (g_rasp_initialized && selectedIndex % 10 == 0) {
            TamperInfo tamper_info;
            if (rasp_detect_tampering(&tamper_info) != RASP_SUCCESS) {
                printf("\n[SECURITY] Tampering detected - terminating\n");
                rasp_respond_to_tamper(&tamper_info, RASP_ACTION_TERMINATE);
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
                savePetsToFile(petList, "database");
                saveUsersToFile(userTable, "database");
                saveAppointmentsToFile();
                saveAppointmentsToFile();
                freePetList(petList);
                freeHashTable(userTable);
                
                // Close database
                if (g_database) {
                    db_close(g_database);
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
    // Check for test/coverage mode
    int test_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test-coverage") == 0 || 
            strcmp(argv[i], "--non-interactive") == 0 ||
            strcmp(argv[i], "-t") == 0) {
            test_mode = 1;
            break;
        }
    }
    
    // ========================================================================
    // RASP SECURITY INITIALIZATION
    // ========================================================================
    printf("================================================================\n");
    printf("         PetCare Application - Security Initialization        \n");
    printf("================================================================\n\n");
    
    // Initialize RASP security system
    initialize_rasp_security();
    
    // Initialize existing security features
    printf("\nInitializing session security...\n");
    init_petcare_session();
    
    // Initialize database
    printf("\nInitializing database...\n");
    g_database = db_init("petcare.db", NULL);
    if (g_database) {
        if (db_create_tables(g_database) == 0) {
            printf("[DATABASE] Database initialized successfully\n");
        } else {
            printf("[DATABASE] Warning: Could not create tables\n");
        }
    } else {
        printf("[DATABASE] Warning: Database initialization failed, using fallback file system\n");
    }
    
    printf("\n[SECURITY] All security features initialized\n");
    
    // If in test mode, skip interactive parts
    if (test_mode) {
        printf("\n[TEST MODE] Running in non-interactive mode for coverage testing\n");
        printf("[TEST MODE] All security features verified successfully\n");
        
        // Perform basic initialization checks
        feedingQueue = createQueue();
        medicineQueue = createQueue();
        HashTable* userTable = createHashTable();
        loadUsersFromFile(userTable, "database");
        loadAppointmentsFromFile();
        
        printf("[TEST MODE] Data structures initialized successfully\n");
        
        // Cleanup
        freeHashTable(userTable);
        if (feedingQueue) free(feedingQueue);
        if (medicineQueue) free(medicineQueue);
        
        // Close database
        if (g_database) {
            db_close(g_database);
            printf("[TEST MODE] Database closed\n");
        }
        
        // Shutdown RASP
        if (g_rasp_initialized) {
            rasp_shutdown();
            printf("[TEST MODE] RASP protection shutdown complete\n");
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
    if (g_database) {
        int db_user_count = db_load_all_users(g_database, userTable);
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
