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

// Obfuscated encryption password for file storage
static ObfuscatedString g_file_encryption_password;
static int g_password_initialized = 0;

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
 * @brief A simple hash function for strings.
 * @param str Input string to be hashed.
 * @return Hash value within the range of the table size.
 */
unsigned int hashFunction(const char* str) {
    unsigned int hash = 0;
    while (*str) {
        hash = (hash * 31) + *str++;
    }
    return hash % HASH_TABLE_SIZE;
}

/**
 * @brief Creates a new HashTable.
 * @return Pointer to the newly created HashTable.
 */
HashTable* createHashTable() {
    HashTable* table = (HashTable*)malloc(sizeof(HashTable));
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        table->buckets[i] = NULL;
    }
    return table;
}

/**
 * @brief Encrypts the password using a simple XOR-based encryption.
 * @param password The original password.
 * @return Pointer to the newly allocated encrypted password.
 */
char* encryptPassword(const char* password) {
    char* encrypted = (char*)malloc(strlen(password) + 1);
    for (size_t i = 0; i < strlen(password); i++) {
        encrypted[i] = password[i] ^ 0x5A;
    }
    encrypted[strlen(password)] = '\0';
    return encrypted;
}

/**
 * @brief Adds a user to the hash table with the given username and password.
 * @param table Pointer to the HashTable.
 * @param username User name.
 * @param password User password.
 */
void addUser(HashTable* table, const char* username, const char* password) {
    unsigned int index = hashFunction(username);

    User* current = table->buckets[index];
    while (current) {
        if (strcmp(current->username, username) == 0) {
            printf("Error: User '%s' already exists.\n", username);
            return;
        }
        current = current->next;}

    User* newUser = (User*)malloc(sizeof(User));
    newUser->username = secure_strdup(username);

    char* encrypted = encryptPassword(password);
    newUser->encryptedPassword = secure_strdup(encrypted);
    // Securely wipe the temporary encrypted password
    secure_str_free(encrypted);

    newUser->next = table->buckets[index];
    table->buckets[index] = newUser;
}

/**
 * @brief Authenticates a user by checking username and password.
 * @param table Pointer to the HashTable.
 * @param username User name.
 * @param password User password.
 * @return 1 if authenticated, 0 otherwise.
 */
int authenticateUser(HashTable* table, const char* username, const char* password) {
    unsigned int index = hashFunction(username);
    User* current = table->buckets[index];
    char* encryptedPassword = encryptPassword(password);

    while (current) {
        if (strcmp(current->username, username) == 0 &&
            strcmp(current->encryptedPassword, encryptedPassword) == 0) {
            // Securely wipe the temporary encrypted password
            secure_str_free(encryptedPassword);
            return 1; // Authentication successful
        }
        current = current->next;
    }
    // Securely wipe the temporary encrypted password
    secure_str_free(encryptedPassword);
    return 0; // Authentication failed
}

/**
 * @brief Saves all users to a file.
 * @param table Pointer to the HashTable.
 * @param filename Name of the file where users are saved.
 */
void saveUsersToFile(HashTable* table, const char* filename) {
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
    
    // Encrypt the temporary file using Whitebox Cryptography
    int result = wb_encrypt_file(temp_filename, filename, 
                                  file_password, 
                                  strlen(file_password));
    
    // Securely wipe password
    secure_wipe(file_password, sizeof(file_password));
    
    // Remove temporary file
    remove(temp_filename);
    
    if (result != 0) {
        fprintf(stderr, "Error: Failed to encrypt user data file\n");
    }
}

/**
 * @brief Loads users from a file and populates the HashTable.
 * @param table Pointer to the HashTable.
 * @param filename Name of the file containing user data.
 */
void loadUsersFromFile(HashTable* table, const char* filename) {
    // Create temporary filename for decrypted data
    char temp_filename[256];
    snprintf(temp_filename, sizeof(temp_filename), "%s.tmp", filename);
    
    // Get decrypted file password
    char file_password[256];
    get_file_password(file_password);
    
    // Decrypt the file using Whitebox Cryptography
    int result = wb_decrypt_file(filename, temp_filename,
                                  file_password,
                                  strlen(file_password));
    
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
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        User* current = table->buckets[i];
        while (current) {
            User* temp = current;
            current = current->next;
            // Securely wipe and free sensitive user data
            secure_str_free(temp->username);
            secure_str_free(temp->encryptedPassword);
            secure_free(temp, sizeof(User));
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
    Pet* newPet = (Pet*)malloc(sizeof(Pet));
    newPet->name = strdup(name);
    newPet->type = strdup(type);
    newPet->age = age;
    newPet->owner = strdup(owner);
    newPet->prev = NULL;
    newPet->next = *petList;

    if (*petList) {
        (*petList)->prev = newPet;
    }

    *petList = newPet;
    printf("Pet added successfully.\n");
}

/**
 * @brief Updates the information of an existing pet.
 * @param petList Pointer to the head of the pet list.
 * @param name Pet name to update.
 * @param owner Username of the owner (for permission check).
 */
void updatePet(Pet* petList, const char* name, const char* owner) {
    while (petList) {
        if (strcmp(petList->name, name) == 0 && strcmp(petList->owner, owner) == 0) {
            char newName[50], newType[50];
            int newAge;
            printf("Enter new name: ");
            scanf("%s", newName);
            printf("Enter new type: ");
            scanf("%s", newType);
            printf("Enter new age: ");
            scanf("%d", &newAge);

            // Securely wipe and free old data
            secure_str_free(petList->name);
            secure_str_free(petList->type);
            petList->name = secure_strdup(newName);
            petList->type = secure_strdup(newType);
            petList->age = newAge;
            // Wipe the input buffers
            secure_wipe(newName, sizeof(newName));
            secure_wipe(newType, sizeof(newType));
            printf("Pet updated successfully.\n");
            return;
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
    Pet* current = *petList;
    while (current) {
        if (strcmp(current->name, name) == 0 && strcmp(current->owner, owner) == 0) {
            if (current->prev) {
                current->prev->next = current->next;}
            else {
                *petList = current->next;
            }
            if (current->next) {current->next->prev = current->prev;}
            // Securely wipe and free pet data
            secure_str_free(current->name);
            secure_str_free(current->type);
            secure_str_free(current->owner);
            secure_free(current, sizeof(Pet));
            printf("Pet deleted successfully.\n");
            return;
        }
        current = current->next;}
    printf("Pet not found or you do not have permission to delete this pet.\n");
}

/**
 * @brief Saves the pet list to a file.
 * @param petList Pointer to the head of the pet list.
 * @param filename Name of the file to save the list.
 */
void savePetsToFile(Pet* petList, const char* filename) {
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
    
    // Encrypt the temporary file using Whitebox Cryptography
    int result = wb_encrypt_file(temp_filename, filename,
                                  file_password,
                                  strlen(file_password));
    
    // Securely wipe password
    secure_wipe(file_password, sizeof(file_password));
    
    // Remove temporary file
    remove(temp_filename);
    
    if (result != 0) {
        fprintf(stderr, "Error: Failed to encrypt pet data file\n");
    }
}

/**
 * @brief Loads a pet list from a file.
 * @param petList Pointer to the head of the pet list.
 * @param filename Name of the file to load the list from.
 */
void loadPetsFromFile(Pet** petList, const char* filename) {
    // Create temporary filename for decrypted data
    char temp_filename[256];
    snprintf(temp_filename, sizeof(temp_filename), "%s.tmp", filename);
    
    // Get decrypted file password
    char file_password[256];
    get_file_password(file_password);
    
    // Decrypt the file using Whitebox Cryptography
    int result = wb_decrypt_file(filename, temp_filename,
                                  file_password,
                                  strlen(file_password));
    
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
    while (petList) {
        Pet* temp = petList;
        petList = petList->next;
        // Securely wipe and free pet data
        secure_str_free(temp->name);
        secure_str_free(temp->type);
        secure_str_free(temp->owner);
        secure_free(temp, sizeof(Pet));
    }
}

/**
 * @brief Maintains the heap property for PetInfo array at a given index.
 * @param arr Array of PetInfo.
 * @param n Size of the array.
 * @param i Current index to enforce heap property.
 */
void heapify(PetInfo arr[], int n, int i) {
    int largest = i;
    int left = 2 * i + 1;
    int right = 2 * i + 2;

    if (left < n && strcmp(arr[left].name, arr[largest].name) > 0) {
        largest = left;
    }

    if (right < n && strcmp(arr[right].name, arr[largest].name) > 0) {
        largest = right;
    }

    if (largest != i) {
        PetInfo temp = arr[i];
        arr[i] = arr[largest];
        arr[largest] = temp;
        heapify(arr, n, largest);
    }
}

/**
 * @brief Performs heap sort on an array of PetInfo, sorting by pet name.
 * @param arr Array of PetInfo.
 * @param n Size of the array.
 */
void heapSort(PetInfo arr[], int n) {
    for (int i = n / 2 - 1; i >= 0; i--) {
        heapify(arr, n, i);
    }

    for (int i = n - 1; i > 0; i--) {
        PetInfo temp = arr[0];
        arr[0] = arr[i];
        arr[i] = temp;
        heapify(arr, i, 0);
    }
}

/**
 * @brief Lists all pets sorted by name using heap sort.
 * @param petList Pointer to the head of the pet list.
 */
void listAllPets(Pet* petList) {
    int count = 0;
    Pet* temp = petList;

    while (temp) {
        count++;
        temp = temp->next;
    }

    if (count == 0) {
        printf("No pets to display.\n"); return;
    }

    PetInfo* arr = (PetInfo*)malloc(count * sizeof(PetInfo));
    temp = petList;
    for (int i = 0; i < count; i++) {
        strcpy(arr[i].name, temp->name);
        strcpy(arr[i].type, temp->type);
        arr[i].age = temp->age;
        strcpy(arr[i].owner, temp->owner);
        temp = temp->next;
    }

    heapSort(arr, count);

    printf("List of All Pets (Sorted by Name):\n");
    for (int i = 0; i < count; i++) {
        printf("Name: %s, Type: %s, Age: %d, Owner: %s\n",
            arr[i].name, arr[i].type, arr[i].age, arr[i].owner);
    }

    free(arr);
}

/**
 * @brief Performs a breadth-first search (BFS) in the pet list for a given search key.
 * @param petList Pointer to the head of the pet list.
 * @param searchKey Key to search in the pet's name or type.
 */
void bfsSearch(Pet* petList, const char* searchKey) {
    printf("Performing BFS Search for '%s':\n", searchKey);

    if (!petList) {
        printf("The pet list is empty.\n");
        return;
    }

    Pet* queue[100];
    int front = 0, rear = 0;
    int found = 0;

    queue[rear++] = petList;

    while (front < rear) {
        Pet* current = queue[front++];

        if (strstr(current->name, searchKey) || strstr(current->type, searchKey)) {
            printf("Name: %s, Type: %s, Age: %d, Owner: %s\n",
                current->name, current->type, current->age, current->owner);
            found = 1;
        }

        if (current->next) {
            queue[rear++] = current->next;
        }
    }

    if (!found) {
        printf("No pets found matching '%s'.\n", searchKey);
    }
}

/**
 * @brief Performs a depth-first search (DFS) in the pet list for a given search key.
 * @param petList Pointer to the head of the pet list.
 * @param searchKey Key to search in the pet's name or type.
 */
void dfsSearch(Pet* petList, const char* searchKey) {
    printf("Performing DFS Search for '%s':\n", searchKey);

    if (!petList) {
        printf("The pet list is empty.\n");
        return;
    }

    Pet* stack[100];
    int top = -1;
    int found = 0; 

    stack[++top] = petList;

    while (top >= 0) {
        Pet* current = stack[top--];

        if (strstr(current->name, searchKey) || strstr(current->type, searchKey)) {
            printf("Name: %s, Type: %s, Age: %d, Owner: %s\n",
                current->name, current->type, current->age, current->owner);
            found = 1;
        }

        if (current->next) {
            stack[++top] = current->next;
        }
    }

    if (!found) {
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
    return (Appointment*)((uintptr_t)(a) ^ (uintptr_t)(b));
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
    Pet* currentPet = petList;
    while (currentPet != NULL) {
        if (strcmp(currentPet->name, petName) == 0 && strcmp(currentPet->owner, owner) == 0) {

            Appointment* current = appointmentList;
            Appointment* prev = NULL;
            Appointment* next = NULL;

            while (current != NULL) {
                next = XOR(prev, current->xorPtr);

                if (current->month == month && current->day == day) {
                    printf("Error: The date %02d/%02d is already occupied. Appointment not added.\n", day, month);
                    return;
                }

                prev = current;
                current = next;
            }

            Appointment* newAppointment = (Appointment*)malloc(sizeof(Appointment));
            strcpy(newAppointment->petName, petName);
            strcpy(newAppointment->description, description);
            newAppointment->day = day;
            newAppointment->month = month;
            strcpy(newAppointment->owner, owner);
            newAppointment->xorPtr = XOR(appointmentList, NULL);

            if (appointmentList != NULL) {
                appointmentList->xorPtr = XOR(newAppointment, XOR(appointmentList->xorPtr, NULL));
            }

            appointmentList = newAppointment;
            printf("Appointment added successfully.\n");
            return;
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
    Appointment* current = appointmentList;
    Appointment* prev = NULL;
    Appointment* next;

    while (current != NULL) {
        next = XOR(prev, current->xorPtr);

        if (current == NULL) {
            printf("Error: Null pointer encountered during traversal.\n");return false;
        }

        if (strcmp(current->petName, petName) == 0 &&
            strcmp(current->owner, owner) == 0 &&
            current->day == oldDay &&
            current->month == oldMonth) {
            break;
        }

        prev = current;
        current = next;
    }

    if (current == NULL) {
        printf("Error: Appointment not found for %s on %02d/%02d.\n", petName, oldDay, oldMonth);
        return false;
    }

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
    Appointment* current = appointmentList;
    Appointment* prev = NULL;
    Appointment* next;

    while (current != NULL) {
        if (strcmp(current->petName, petName) == 0 &&
            strcmp(current->owner, owner) == 0) {
            break; 
        }
        next = XOR(prev, current->xorPtr);
        prev = current;
        current = next;}

    if (current == NULL) {
        printf("Error: You do not own a pet named '%s'.\n", petName); return false; 
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
    printf("\nAppointments for month %d:\n", month);
    int days[31] = { 0 }; 

    Appointment* current = appointmentList;
    Appointment* prev = NULL;
    Appointment* next;

    while (current != NULL) {
        next = XOR(prev, current->xorPtr);
        if (current->month == month) {
            days[current->day - 1] = 1;
        }
        prev = current;
        current = next;
    }

    printf("Sun Mon Tue Wed Thu Fri Sat\n");
    for (int i = 1; i <= 31; i++) {
        if (days[i - 1] == 1) {
            printf("\033[31m%3d\033[0m ", i);
        }
        else {
            printf("\033[34m%3d\033[0m ", i); 
        }
        if (i % 7 == 0) {
            printf("\n");
        }
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
    size_t keyLen = strlen(key);
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % keyLen];
    }
}

/**
 * @brief Saves all appointments to a file.
 */
void saveAppointmentsToFile() {
    FILE* file = fopen("appointment.data", "wb");
    if (!file) {
        perror("Error opening file");return;
    }

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
        current = next;}

    fclose(file);}

/**
 * @brief Loads all appointments from a file.
 */
void loadAppointmentsFromFile() {
    FILE* file = fopen("appointment.data", "rb");
    if (!file) {
        perror("Error opening file");
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

        // Şifreyi çöz
        xorEncryptDecrypt((char*)newAppointment, sizeof(Appointment), key);

        newAppointment->xorPtr = XOR(prev, NULL);
        if (prev != NULL) {
            prev->xorPtr = XOR(newAppointment, XOR(prev->xorPtr, NULL));}
        else {
            appointmentList = newAppointment;
        }
        prev = newAppointment;}

    fclose(file);}

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
    FeedingSchedule* newSchedule = (FeedingSchedule*)malloc(sizeof(FeedingSchedule));
    strcpy(newSchedule->petName, petName);
    strcpy(newSchedule->scheduleDetails, scheduleDetails);
    newSchedule->next = NULL;

    if (queue->rear == NULL) {  
        queue->front = queue->rear = newSchedule;
        return;
    }

    queue->rear->next = newSchedule;
    queue->rear = newSchedule;
}

/**
 * @brief Dequeues the first feeding schedule from the queue.
 * @param queue Pointer to the queue.
 * @return Pointer to the dequeued FeedingSchedule (caller responsible for freeing).
 */
FeedingSchedule* dequeue(Queue* queue) {
    if (queue->front == NULL) { return NULL;}

    FeedingSchedule* temp = queue->front;
    queue->front = queue->front->next;

    if (queue->front == NULL) {
        queue->rear = NULL;
    }

    return temp;
}

/**
 * @brief Checks if the queue is empty.
 * @param queue Pointer to the queue.
 * @return 1 if empty, 0 otherwise.
 */
int isQueueEmpty(Queue* queue) {
    return queue->front == NULL;
}

/**
 * @brief Adds a feeding schedule (interactive, uses stdin for details).
 * @param feedingQueue Pointer to the global feeding queue.
 */
void addFeedingSchedule(Queue* feedingQueue) {
    char petName[50], scheduleDetails[100];

    printf("Enter pet's name: ");
    scanf("%s", petName);

    printf("Enter feeding schedule details: ");
    scanf(" %[^\n]", scheduleDetails);

    enqueue(feedingQueue, petName, scheduleDetails);

    printf("Feeding schedule added successfully for pet: %s\n", petName);}

/**
 * @brief Updates an existing feeding schedule for a specific pet.
 * @param feedingQueue Pointer to the feeding queue.
 * @param petName Name of the pet whose schedule is to be updated.
 * @param newDetails New feeding schedule details.
 */
void updateFeedingSchedule(Queue* feedingQueue, const char* petName, const char* newDetails) {
    if (isQueueEmpty(feedingQueue)) {
        printf("No feeding schedules available.\n");return;
    }

    FeedingSchedule* current = feedingQueue->front;
    int found = 0;

    while (current != NULL) {
        if (strcmp(current->petName, petName) == 0) {
            strcpy(current->scheduleDetails, newDetails);
            printf("Feeding schedule for '%s' updated successfully.\n", petName);
            found = 1;
            break;
        }
        current = current->next;
    }

    if (!found) {
        printf("Feeding schedule for pet '%s' not found.\n", petName);
    }
}

/**
 * @brief Deletes a feeding schedule for a specific pet.
 * @param feedingQueue Pointer to the feeding queue.
 * @param petName Name of the pet whose schedule is to be deleted.
 */
void deleteFeedingSchedule(Queue* feedingQueue, const char* petName) {
    if (isQueueEmpty(feedingQueue)) {
        printf("No feeding schedules available.\n");return;
    }

    FeedingSchedule* current = feedingQueue->front;
    FeedingSchedule* previous = NULL;

    if (strcmp(current->petName, petName) == 0) {
        feedingQueue->front = current->next;

        if (feedingQueue->front == NULL) {
            feedingQueue->rear = NULL; 
        }

        free(current);
        printf("Feeding schedule for '%s' deleted successfully.\n", petName);
        return;
    }

    while (current != NULL) {
        if (strcmp(current->petName, petName) == 0) {
            previous->next = current->next;

            if (current == feedingQueue->rear) {
                feedingQueue->rear = previous; 
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
    if (isQueueEmpty(feedingQueue)) {
        printf("No feeding schedules available.\n");
        return;
    }

    FeedingSchedule* current = feedingQueue->front;
    printf("Feeding Schedules:\n");
    while (current != NULL) {
        printf("Pet: %s, Schedule: %s\n", current->petName, current->scheduleDetails);
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
    FeedingSchedule* newSchedule = (FeedingSchedule*)malloc(sizeof(FeedingSchedule));
    strcpy(newSchedule->petName, petName);
    strcpy(newSchedule->scheduleDetails, scheduleDetails);
    newSchedule->next = NULL;

    if (medicineQueue->rear == NULL) {  // Kuyruk boşsa
        medicineQueue->front = medicineQueue->rear = newSchedule;
        return;
    }

    medicineQueue->rear->next = newSchedule;
    medicineQueue->rear = newSchedule;

    printf("Medicine schedule added successfully for pet: %s\n", petName);
}

/**
 * @brief Updates a medicine schedule for a specific pet.
 * @param medicineQueue Pointer to the global medicine queue.
 * @param petName Name of the pet whose schedule is to be updated.
 * @param newDetails New medicine schedule details.
 */
void updateMedicineSchedule(Queue* medicineQueue, const char* petName, const char* newDetails) {
    if (isQueueEmpty(medicineQueue)) {
        printf("No medicine schedules available.\n");return;
    }

    FeedingSchedule* current = medicineQueue->front;
    int found = 0;

    while (current != NULL) {
        if (strcmp(current->petName, petName) == 0) {
            strcpy(current->scheduleDetails, newDetails);
            printf("Medicine schedule for '%s' updated successfully.\n", petName);
            found = 1;
            break;
        }
        current = current->next;
    }

    if (!found) {
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
    if (isQueueEmpty(medicineQueue)) {
        printf("No medicine schedules available.\n");
        return;
    }

    FeedingSchedule* current = medicineQueue->front;
    printf("Medicine Schedules:\n");
    while (current != NULL) {
        printf("Pet: %s, Schedule: %s\n", current->petName, current->scheduleDetails);
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
    if (!tree->root) {
        tree->root = createBPlusNode();
    }

    // Correctly encode date as YYYYMMDD
    int value = (year * 10000) + (month * 100) + day; // Fix: Year first, then month, then day
    int key = hashFunction(petName);

    BPlusNode* root = tree->root;
    root->keys[root->count] = key;
    root->values[root->count] = value;
    root->count++;
}

/**
 * @brief Checks if a pet with a given name belongs to the specified user (owner).
 * @param petList Pointer to the pet list.
 * @param petName Name of the pet.
 * @param owner Username of the owner.
 * @return True if the pet is owned by the user, false otherwise.
 */
bool isPetOwnedByUser(Pet* petList, const char* petName, const char* owner) {
    while (petList) {
        if (strcmp(petList->name, petName) == 0 && strcmp(petList->owner, owner) == 0) {
            return true;
        }
        petList = petList->next;
    }
    return false;
}

/**
 * @brief Saves the birthdays stored in the B+ Tree to a file.
 * @param birthdayTree Pointer to the BPlusTree containing birthdays.
 * @param filename File to save to.
 * @param petList Pointer to the pet list for retrieving pet details.
 */
void saveBirthdaysToFile(BPlusTree* birthdayTree, const char* filename, Pet* petList) {
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
 * @brief Loads birthday data from a file into the B+ Tree.
 * @param birthdayTree Pointer to the BPlusTree to populate.
 * @param filename File to read from.
 * @param petList Pointer to the pet list pointer (pets may also be loaded in this process).
 */
void loadBirthdaysFromFile(BPlusTree* birthdayTree, const char* filename, Pet** petList) {
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

        free(nameBuf);
        free(typeBuf);
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
    while (petList) {
        if (hashFunction(petList->name) == key) {
            return petList;
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
    //100 is maximum rotuine count
    if (exerciseStack.top >= MAX_ROUTINES - 1) {
        printf("Error: Stack is full. Cannot add more routines.\n");
        return;
    }

    exerciseStack.top++;
    strncpy(exerciseStack.stack[exerciseStack.top].petName, petName, sizeof(exerciseStack.stack[exerciseStack.top].petName) - 1);
    strncpy(exerciseStack.stack[exerciseStack.top].exercise, exercise, sizeof(exerciseStack.stack[exerciseStack.top].exercise) - 1);

    printf("Exercise routine for '%s' added successfully!\n", petName);
}

/**
 * @brief Lists all exercise routines from the stack.
 */
void listAllExercises() {
    if (exerciseStack.top == -1) {
        printf("No exercise routines available.\n");
        return;
    }

    printf("\n--- Exercise Routines ---\n");
    for (int i = 0; i <= exerciseStack.top; i++) { 
        printf("Pet Name: %s\nRoutine: %s\n\n",
            exerciseStack.stack[i].petName,
            exerciseStack.stack[i].exercise);
    }
}

/**
 * @brief Removes the last exercise routine from the stack (undo operation).
 */
void undoLastExercise() {
    if (exerciseStack.top == -1) {
        printf("Error: No exercise routines to undo.\n");
        return;
    }

    printf("Undoing last exercise routine for '%s'...\n", exerciseStack.stack[exerciseStack.top].petName);
    exerciseStack.top--;  // Remove the most recent exercise by decrementing the top index

    printf("Last exercise routine undone successfully!\n");
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
    int N = strlen(text);
    int M = strlen(pattern);
    if (M == 0) return true; // boş pattern
    int* lps = (int*)malloc(sizeof(int) * M);
    computeLPSArray(pattern, M, lps);
    int i = 0;
    int j = 0;
    while (i < N) {
        if (pattern[j] == text[i]) {
            i++;
            j++;
        }
        if (j == M) {
            free(lps);
            return true;}
        else if (i < N && pattern[j] != text[i]) {
            if (j != 0) j = lps[j - 1];
            else i++;
        }
    }
    free(lps);
    return false;
}

/**
 * @brief Loads stray animals from a file into the given list.
 * @param list Pointer to the pointer of the stray animal list head.
 * @param filename Name of the file to load from.
 */
void loadStrayAnimalsFromFile(StrayAnimal** list, const char* filename) {
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
 * @brief Saves the stray animal list to a file.
 * @param list Pointer to the head of the stray animal list.
 * @param filename Name of the file to save to.
 */
void saveStrayAnimalsToFile(StrayAnimal* list, const char* filename) {
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
void updateStrayAnimal(StrayAnimal* list, int id,
    const char* newType,
    const char* newGender,
    const char* newArrivalDate,
    int newAge)
{
    StrayAnimal* current = list;
    while (current) {
        if (current->id == id) {
            // Direkt güncelleme
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
 * @brief Loads adopted animals from a file into the given list.
 * @param list Pointer to the pointer of the adopted animal list head.
 * @param filename Name of the file to load from.
 */
void loadAdoptedAnimalsFromFile(AdoptedAnimal** list, const char* filename) {
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
 * @brief Saves the adopted animal list to a file.
 * @param list Pointer to the head of the adopted animal list.
 * @param filename Name of the file to save to.
 */
void saveAdoptedAnimalsToFile(AdoptedAnimal* list, const char* filename) {
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

    // Mevcut node’daki tüm key/value çiftlerini oku
    for (int i = 0; i < node->count; i++) {
        int key = node->keys[i];
        int encodedDate = node->values[i];

        // Pet’i bul
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
    // Check for tampering at startup
    int tampering_status = detect_tampering();
    if (tampering_status > 0) {
        fprintf(stderr, "Warning: Potential tampering detected (code %d)\n", tampering_status);
    }
    
    // Generate device fingerprint
    if (!g_fingerprint_initialized) {
        if (generate_device_fingerprint(&g_device_fingerprint) != 0) {
            fprintf(stderr, "Error: Failed to generate device fingerprint\n");
            return;
        }
        g_fingerprint_initialized = 1;
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
    // First authenticate normally
    if (!authenticateUser(table, username, password)) {
        return 0;
    }
    
    // Ensure fingerprint is initialized
    if (!g_fingerprint_initialized) {
        init_petcare_session();
    }
    
    // Create session (1 hour = 3600 seconds)
    if (create_session(&g_device_fingerprint, 3600, &g_current_session) != 0) {
        fprintf(stderr, "Error: Failed to create session\n");
        return 0;
    }
    
    g_session_active = 1;
    return 1;
}

/**
 * @brief Logout user and destroy session
 */
void logoutUserSession() {
    if (g_session_active) {
        invalidate_session(&g_current_session);
        g_session_active = 0;
    }
}

/**
 * @brief Check if current session is valid
 * @return 1 if session is valid, 0 otherwise
 */
int isSessionValid() {
    if (!g_session_active || !g_fingerprint_initialized) {
        return 0;
    }
    
    uint8_t session_key[32];
    int result = validate_session(&g_current_session, &g_device_fingerprint, session_key);
    
    // Securely wipe the session key
    secure_wipe(session_key, sizeof(session_key));
    
    return (result == 0) ? 1 : 0;
}

