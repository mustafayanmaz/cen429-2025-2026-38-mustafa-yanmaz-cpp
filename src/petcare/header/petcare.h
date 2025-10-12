/**
 * @file petcare.h
 */
#ifndef PETCARE_H
#define PETCARE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "database.h"

/**
 * @brief The size of the Hash Table (for user management).
 */
#define HASH_TABLE_SIZE 100

 /**
  * @brief Represents a single user in the system.
  */
typedef struct User {
    char* username;                 /**< Username */
    char* encryptedPassword;        /**< Encrypted password */
    struct User* next;             /**< Pointer to the next user in case of collision */
} User;

/**
 * @brief Represents a hash table for user management.
 */
typedef struct HashTable {
    User* buckets[HASH_TABLE_SIZE]; /**< Array of user lists (buckets) */
} HashTable;

/**
 * @brief Creates a new HashTable.
 * @return Pointer to the newly created HashTable.
 */
HashTable* createHashTable();

/**
 * @brief A simple hash function for strings.
 * @param str Input string to be hashed.
 * @return Hash value within the range of the table size.
 */
unsigned int hashFunction(const char* str);

/**
 * @brief Adds a user to the hash table with the given username and password.
 * @param table Pointer to the HashTable.
 * @param username User name.
 * @param password User password.
 */
void addUser(HashTable* table, const char* username, const char* password);

/**
 * @brief Authenticates a user by checking username and password.
 * @param table Pointer to the HashTable.
 * @param username User name.
 * @param password User password.
 * @return 1 if authenticated, 0 otherwise.
 */
int authenticateUser(HashTable* table, const char* username, const char* password);

/**
 * @brief Saves all users to a file.
 * @param table Pointer to the HashTable.
 * @param filename Name of the file where users are saved.
 */
void saveUsersToFile(HashTable* table, const char* filename);

/**
 * @brief Loads users from a file and populates the HashTable.
 * @param table Pointer to the HashTable.
 * @param filename Name of the file containing user data.
 */
void loadUsersFromFile(HashTable* table, const char* filename);

/**
 * @brief Encrypts the password using a simple XOR-based encryption.
 * @param password The original password.
 * @return Pointer to the newly allocated encrypted password.
 */
char* encryptPassword(const char* password);

/**
 * @brief Frees all memory used by the HashTable.
 * @param table Pointer to the HashTable to be freed.
 */
void freeHashTable(HashTable* table);

/**
 * @brief Represents a Pet entity.
 */
typedef struct Pet {
    char* name;              /**< Pet name */
    char* type;              /**< Pet type (e.g., dog, cat, etc.) */
    int age;                 /**< Pet age */
    char* owner;             /**< Pet owner username */
    struct Pet* prev;        /**< Pointer to the previous pet (for double linked list) */
    struct Pet* next;        /**< Pointer to the next pet (for double linked list) */
} Pet;

/**
 * @brief Adds a Pet to the pet list.
 * @param petList Pointer to the head of the pet list.
 * @param name Name of the pet.
 * @param type Type of the pet (e.g., dog, cat).
 * @param age Age of the pet.
 * @param owner Username of the owner.
 */
void addPet(Pet** petList, const char* name, const char* type, int age, const char* owner);

/**
 * @brief Updates the information of an existing pet.
 * @param petList Pointer to the head of the pet list.
 * @param name Pet name to update.
 * @param owner Username of the owner (for permission check).
 */
void updatePet(Pet* petList, const char* name, const char* owner);

/**
 * @brief Deletes a pet from the list if owned by the user.
 * @param petList Pointer to the head of the pet list.
 * @param name Pet name to delete.
 * @param owner Username of the owner (for permission check).
 */
void deletePet(Pet** petList, const char* name, const char* owner);

/**
 * @brief Saves the pet list to a file.
 * @param petList Pointer to the head of the pet list.
 * @param filename Name of the file to save the list.
 */
void savePetsToFile(Pet* petList, const char* filename);

/**
 * @brief Loads a pet list from a file.
 * @param petList Pointer to the head of the pet list.
 * @param filename Name of the file to load the list from.
 */
void loadPetsFromFile(Pet** petList, const char* filename);

/**
 * @brief Frees all memory used by the pet list.
 * @param petList Pointer to the head of the pet list.
 */
void freePetList(Pet* petList);

/**
 * @brief Represents minimal pet information for heap sort usage.
 */
typedef struct PetInfo {
    char name[50];      /**< Pet name */
    char type[50];      /**< Pet type */
    int age;            /**< Pet age */
    char owner[50];     /**< Owner's name */
} PetInfo;

/**
 * @brief Maintains the heap property for PetInfo array at a given index.
 * @param arr Array of PetInfo.
 * @param n Size of the array.
 * @param i Current index to enforce heap property.
 */
void heapify(PetInfo arr[], int n, int i);

/**
 * @brief Performs heap sort on an array of PetInfo, sorting by pet name.
 * @param arr Array of PetInfo.
 * @param n Size of the array.
 */
void heapSort(PetInfo arr[], int n);

/**
 * @brief Lists all pets sorted by name using heap sort.
 * @param petList Pointer to the head of the pet list.
 */
void listAllPets(Pet* petList);

/**
 * @brief Performs a breadth-first search (BFS) in the pet list for a given search key.
 * @param petList Pointer to the head of the pet list.
 * @param searchKey Key to search in the pet's name or type.
 */
void bfsSearch(Pet* petList, const char* searchKey);

/**
 * @brief Performs a depth-first search (DFS) in the pet list for a given search key.
 * @param petList Pointer to the head of the pet list.
 * @param searchKey Key to search in the pet's name or type.
 */
void dfsSearch(Pet* petList, const char* searchKey);

/**
 * @brief Represents an appointment node in an XOR linked list.
 */
typedef struct Appointment {
    char petName[50];      /**< Name of the pet */
    char description[100]; /**< Appointment description */
    int day;               /**< Day of the appointment */
    int month;             /**< Month of the appointment */
    char owner[50];        /**< Owner's username */
    struct Appointment* xorPtr; /**< XOR pointer to next/previous node */
} Appointment;

/**
 * @brief XORs two Appointment pointers.
 * @param a First Appointment pointer.
 * @param b Second Appointment pointer.
 * @return XOR of the two pointers.
 */
Appointment* XOR(Appointment* a, Appointment* b);

/**
 * @brief Adds an appointment for a pet if user owns the pet and the date is free.
 * @param petName The pet's name.
 * @param description Appointment description.
 * @param day Day of the appointment.
 * @param month Month of the appointment.
 * @param owner Owner's username.
 * @param petList The pet list for ownership verification.
 */
void addAppointment(const char* petName, const char* description, int day, int month, const char* owner, Pet* petList);

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
bool updateAppointment(const char* petName, int oldDay, int oldMonth, int newDay, int newMonth, const char* newDescription, const char* owner);

/**
 * @brief Cancels an existing appointment.
 * @param petName The pet's name.
 * @param day Day of the appointment to cancel.
 * @param month Month of the appointment to cancel.
 * @param owner Owner's username (for permission check).
 * @return True if cancelation succeeds, false otherwise.
 */
bool cancelAppointment(const char* petName, int day, int month, const char* owner);

/**
 * @brief Views the appointments for a given month in a formatted view.
 * @param month Month to view.
 */
void viewAppointments(int month);

/**
 * @brief Saves all appointments to a file.
 */
void saveAppointmentsToFile();

/**
 * @brief Loads all appointments from a file.
 */
void loadAppointmentsFromFile();

/**
 * @brief Represents a feeding schedule in a queue.
 */
typedef struct FeedingSchedule {
    char petName[50];           /**< Name of the pet */
    char scheduleDetails[100];  /**< Details of the feeding schedule */
    struct FeedingSchedule* next; /**< Pointer to next schedule in queue */
} FeedingSchedule;

/**
 * @brief Represents a queue data structure for feeding schedules.
 */
typedef struct Queue {
    FeedingSchedule* front; /**< Front of the queue */
    FeedingSchedule* rear;  /**< Rear of the queue */
} Queue;

/**
 * @brief Global feeding schedule queue.
 */
extern Queue* feedingQueue;

/**
 * @brief Global medicine schedule queue.
 */
extern Queue* medicineQueue;

/**
 * @brief Creates and returns an empty queue.
 * @return Pointer to the newly created queue.
 */
Queue* createQueue();

/**
 * @brief Enqueues a new feeding schedule into the queue.
 * @param queue Pointer to the queue.
 * @param petName Name of the pet.
 * @param scheduleDetails Details of the feeding schedule.
 */
void enqueue(Queue* queue, const char* petName, const char* scheduleDetails);

/**
 * @brief Dequeues the first feeding schedule from the queue.
 * @param queue Pointer to the queue.
 * @return Pointer to the dequeued FeedingSchedule (caller responsible for freeing).
 */
FeedingSchedule* dequeue(Queue* queue);

/**
 * @brief Checks if the queue is empty.
 * @param queue Pointer to the queue.
 * @return 1 if empty, 0 otherwise.
 */
int isQueueEmpty(Queue* queue);

/**
 * @brief Adds a feeding schedule (interactive, uses stdin for details).
 * @param feedingQueue Pointer to the global feeding queue.
 */
void addFeedingSchedule(Queue* feedingQueue);

/**
 * @brief Updates an existing feeding schedule for a specific pet.
 * @param feedingQueue Pointer to the feeding queue.
 * @param petName Name of the pet whose schedule is to be updated.
 * @param newDetails New feeding schedule details.
 */
void updateFeedingSchedule(Queue* feedingQueue, const char* petName, const char* newDetails);

/**
 * @brief Deletes a feeding schedule for a specific pet.
 * @param feedingQueue Pointer to the feeding queue.
 * @param petName Name of the pet whose schedule is to be deleted.
 */
void deleteFeedingSchedule(Queue* feedingQueue, const char* petName);

/**
 * @brief Views all feeding schedules in the queue.
 * @param feedingQueue Pointer to the feeding queue.
 */
void viewFeedingSchedules(Queue* feedingQueue);

/**
 * @brief Adds a medicine schedule for a pet.
 * @param medicineQueue Pointer to the global medicine queue.
 * @param petName Name of the pet.
 * @param scheduleDetails Details of the medicine schedule.
 */
void addMedicineSchedule(Queue* medicineQueue, const char* petName, const char* scheduleDetails);

/**
 * @brief Updates a medicine schedule for a specific pet.
 * @param medicineQueue Pointer to the global medicine queue.
 * @param petName Name of the pet whose schedule is to be updated.
 * @param newDetails New medicine schedule details.
 */
void updateMedicineSchedule(Queue* medicineQueue, const char* petName, const char* newDetails);

/**
 * @brief Deletes a medicine schedule for a specific pet.
 * @param medicineQueue Pointer to the global medicine queue.
 * @param petName Name of the pet whose schedule is to be deleted.
 */
void deleteMedicineSchedule(Queue* medicineQueue, const char* petName);

/**
 * @brief Views all medicine schedules in the queue.
 * @param medicineQueue Pointer to the global medicine queue.
 */
void viewMedicineSchedules(Queue* medicineQueue);

/**
 * @brief Analyzes medicine schedule dependencies using SCC (Strongly Connected Components) algorithm.
 */
void findSCC();

/**
 * @brief Represents a node in a B+ Tree.
 */
typedef struct BPlusNode {
    int keys[10];                /**< Keys stored in the node */
    int values[10];              /**< Associated integer values (like dates) */
    int count;                   /**< Number of keys in this node */
    struct BPlusNode* children[10]; /**< Children pointers for B+ tree */
} BPlusNode;

/**
 * @brief Represents a B+ Tree structure.
 */
typedef struct BPlusTree {
    BPlusNode* root;            /**< Pointer to the root node of the B+ tree */
} BPlusTree;

/**
 * @brief Creates and returns an empty B+ Tree.
 * @return Pointer to the newly created BPlusTree.
 */
BPlusTree* createBPlusTree();

/**
 * @brief Inserts a birthday record into the B+ Tree.
 * @param tree Pointer to the BPlusTree.
 * @param petName The name of the pet.
 * @param day Day of the birthday.
 * @param month Month of the birthday.
 * @param year Year of the birthday.
 */
void insertBirthday(BPlusTree* tree, const char* petName, int day, int month, int year);

/**
 * @brief Checks if a pet with a given name belongs to the specified user (owner).
 * @param petList Pointer to the pet list.
 * @param petName Name of the pet.
 * @param owner Username of the owner.
 * @return True if the pet is owned by the user, false otherwise.
 */
bool isPetOwnedByUser(Pet* petList, const char* petName, const char* owner);

/**
 * @brief Represents a date (day/month/year).
 */
typedef struct Date {
    int day;   /**< Day */
    int month; /**< Month */
    int year;  /**< Year */
} Date;

/**
 * @brief Saves the birthdays stored in the B+ Tree to a file.
 * @param birthdayTree Pointer to the BPlusTree containing birthdays.
 * @param filename File to save to.
 * @param petList Pointer to the pet list for retrieving pet details.
 */
void saveBirthdaysToFile(BPlusTree* birthdayTree, const char* filename, Pet* petList);

/**
 * @brief Finds a pet by its hashed name key.
 * @param petList Pointer to the pet list.
 * @param key Hashed key of the pet's name.
 * @return Pointer to the Pet if found, NULL otherwise.
 */
Pet* findPetByName(Pet* petList, int key);

/**
 * @brief Recursively saves a B+ tree node to file.
 * @param node Pointer to the B+ tree node.
 * @param file File pointer.
 * @param petList Pointer to the pet list for retrieving pet details.
 */
void saveBPlusTreeToFile(BPlusNode* node, FILE* file, Pet* petList);

/**
 * @brief Loads birthday data from a file into the B+ Tree.
 * @param birthdayTree Pointer to the BPlusTree to populate.
 * @param filename File to read from.
 * @param petList Pointer to the pet list pointer (pets may also be loaded in this process).
 */
void loadBirthdaysFromFile(BPlusTree* birthdayTree, const char* filename, Pet** petList);

/**
 * @brief Lists all pet birthdays stored in the B+ Tree.
 * @param birthdayTree Pointer to the BPlusTree.
 * @param petList Pointer to the pet list.
 */
void listPetBirthdays(BPlusTree* birthdayTree, Pet* petList);

/**
 * @brief Adds an exercise routine for a pet, pushing it onto a stack.
 * @param petName Name of the pet.
 * @param exercise Description of the exercise routine.
 */
void addExerciseRoutine(const char* petName, const char* exercise);

/**
 * @brief Lists all exercise routines from the stack.
 */
void listAllExercises();

/**
 * @brief Removes the last exercise routine from the stack (undo operation).
 */
void undoLastExercise();

/**
 * @brief Maximum number of routines in the exercise stack.
 */
#define MAX_ROUTINES 100

 /**
  * @brief Represents a single exercise routine entry.
  */
typedef struct {
    char petName[50];     /**< Pet name */
    char exercise[100];   /**< Exercise description */
} ExerciseRoutine;

/**
 * @brief Represents the stack of exercise routines.
 */
typedef struct {
    ExerciseRoutine stack[MAX_ROUTINES]; /**< Array-based stack of routines */
    int top;                             /**< Index of the top element (-1 if empty) */
} ExerciseStack;

/**
 * @brief Global exercise stack variable.
 */
extern ExerciseStack exerciseStack;

/**
 * @brief Represents a stray animal.
 */
typedef struct StrayAnimal {
    int id;                         /**< Unique ID of the stray animal */
    char type[50];                  /**< Type of the stray animal */
    char gender[10];                /**< Gender of the stray animal */
    char arrivalDate[20];           /**< Arrival date at the shelter */
    int age;                        /**< Age of the animal */
    struct StrayAnimal* next;       /**< Pointer to the next stray animal */
} StrayAnimal;

/**
 * @brief Represents an adopted animal.
 */
typedef struct AdoptedAnimal {
    int id;                         /**< Unique ID of the adopted animal */
    char type[50];                  /**< Type of the adopted animal */
    char gender[10];                /**< Gender of the adopted animal */
    char arrivalDate[20];           /**< Arrival date at the shelter */
    int age;                        /**< Age of the animal */
    char owner[50];                 /**< Username of the adopter */
    char adoptionDate[20];          /**< Date of adoption */
    struct AdoptedAnimal* next;     /**< Pointer to the next adopted animal */
} AdoptedAnimal;

/**
 * @brief Adopts a stray animal, removing it from the stray list and adding it to the adopted list.
 * @param strayList Pointer to the pointer of the stray list head.
 * @param activeUser Username of the currently logged-in user who is adopting.
 * @param chosenID The ID of the stray animal to adopt.
 * @param newName The new name given to the animal.
 * @param adoptionDate The date of adoption.
 */
void adoptStrayAnimal(StrayAnimal** strayList,
    const char* activeUser,
    int chosenID,
    const char* newName,
    const char* adoptionDate);

/**
 * @brief Loads stray animals from a file into the given list.
 * @param list Pointer to the pointer of the stray animal list head.
 * @param filename Name of the file to load from.
 */
void loadStrayAnimalsFromFile(StrayAnimal** list, const char* filename);

/**
 * @brief Saves the stray animal list to a file.
 * @param list Pointer to the head of the stray animal list.
 * @param filename Name of the file to save to.
 */
void saveStrayAnimalsToFile(StrayAnimal* list, const char* filename);

/**
 * @brief Adds a stray animal to the list.
 * @param list Pointer to the pointer of the stray animal list head.
 * @param type Type of the stray animal.
 * @param gender Gender of the stray animal.
 * @param arrivalDate Arrival date string.
 * @param age Age of the animal.
 */
void addStrayAnimalToList(StrayAnimal** list, const char* type, const char* gender,
    const char* arrivalDate, int age);

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
);

/**
 * @brief Deletes a stray animal from the list by ID.
 * @param list Pointer to the pointer of the stray animal list head.
 * @param id ID of the animal to delete.
 */
void deleteStrayAnimal(StrayAnimal** list, int id);

/**
 * @brief Lists all stray animals currently available.
 * @param list Pointer to the head of the stray animal list.
 */
void listStrayAnimals(StrayAnimal* list);

/**
 * @brief Uses KMP to search for stray animals whose type contains the searchKey.
 * @param list Pointer to the head of the stray animal list.
 * @param searchKey Substring to search for in the animal's type.
 */
void searchStrayAnimalsKMP(StrayAnimal* list, const char* searchKey);

/**
 * @brief Uses a helper KMP function to check if a pattern is contained within a text.
 * @param text The main text.
 * @param pattern The substring/pattern.
 * @return True if the pattern is found, false otherwise.
 */
bool KMPcontains(const char* text, const char* pattern);

/**
 * @brief Loads adopted animals from a file into the given list.
 * @param list Pointer to the pointer of the adopted animal list head.
 * @param filename Name of the file to load from.
 */
void loadAdoptedAnimalsFromFile(AdoptedAnimal** list, const char* filename);

/**
 * @brief Saves the adopted animal list to a file.
 * @param list Pointer to the head of the adopted animal list.
 * @param filename Name of the file to save to.
 */
void saveAdoptedAnimalsToFile(AdoptedAnimal* list, const char* filename);

/**
 * @brief Adopts a stray animal (no new name scenario).
 * @param strayList Pointer to the pointer of the stray list head.
 * @param activeUser Username of the currently logged-in user who is adopting.
 */
void adoptStrayAnimal(StrayAnimal** strayList, const char* activeUser);

/**
 * @brief Lists all adopted animals.
 * @param list Pointer to the head of the adopted animal list.
 */
void listAllAdoptedAnimals(AdoptedAnimal* list);

// ============================================================================
// Session Management Functions (Asset Protection)
// ============================================================================

/**
 * @brief Initialize device fingerprint and anti-tampering checks
 */
void init_petcare_session();

/**
 * @brief Login user with session creation and device binding
 * @param table Pointer to the HashTable
 * @param username User name
 * @param password User password
 * @return 1 if authenticated and session created, 0 otherwise
 */
int loginUserWithSession(HashTable* table, const char* username, const char* password);

/**
 * @brief Logout user and destroy session
 */
void logoutUserSession();

/**
 * @brief Check if current session is valid
 * @return 1 if session is valid, 0 otherwise
 */
int isSessionValid();

// ============================================================================
// Database Management Functions
// ============================================================================

/**
 * @brief Global database handle
 */
extern struct Database* g_petcare_db;

/**
 * @brief Initialize the PetCare database
 * @param db_path Path to the database file
 * @return 0 on success, non-zero on failure
 */
int init_petcare_database(const char* db_path);

/**
 * @brief Close the PetCare database
 */
void close_petcare_database();

/**
 * @brief Get the global database handle
 * @return Pointer to the global database handle
 */
struct Database* get_petcare_database();

/**
 * @brief Migrate data from .dat files to SQLite database
 * @return 0 on success, non-zero on failure
 */
int migrate_dat_to_sqlite();

#endif
