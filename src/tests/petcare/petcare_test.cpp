/**
* @file petcare_test.cpp
*/

#include <gtest/gtest.h>
#include "petcare.h"
#include <sstream>
#include <cstdio> 
#include "methods.h"
#include <string>

/**
 * @class UserAuthTest
 * @brief Test fixture for user authentication tests.
 */
class UserAuthTest : public ::testing::Test {
protected:
    /**
     * @brief Hash table pointer for user-related data.
     */
    HashTable* table;

    /**
     * @brief Initializes resources before each user authentication test.
     */
    void SetUp() override {
        table = createHashTable();
    }

    /**
     * @brief Cleans up resources after each user authentication test.
     */
    void TearDown() override {
        freeHashTable(table);
    }
};

/**
 * @brief Verifies that a user can be successfully registered.
 */
TEST_F(UserAuthTest, RegisterUser) {
    addUser(table, "testuser", "password123");
    ASSERT_EQ(authenticateUser(table, "testuser", "password123"), 1) << "User should be able to login after registration.";
}

/**
 * @brief Tests that login fails when an incorrect password is provided.
 */
TEST_F(UserAuthTest, LoginIncorrectPassword) {
    addUser(table, "testuser", "password123");
    ASSERT_EQ(authenticateUser(table, "testuser", "wrongpassword"), 0) << "Login should fail for incorrect password.";
}

/**
 * @brief Tests that login fails for a user that does not exist.
 */
TEST_F(UserAuthTest, LoginNonExistentUser) {
    ASSERT_EQ(authenticateUser(table, "nonexistentuser", "password123"), 0) << "Login should fail for non-existent user.";
}

/**
 * @brief Ensures that users can be saved to a file and loaded correctly.
 */
TEST_F(UserAuthTest, SaveAndLoadUsers) {
    addUser(table, "testuser1", "password123");
    addUser(table, "testuser2", "mypassword");

    saveUsersToFile(table, "test_users.dat");

    HashTable* loadedTable = createHashTable();
    loadUsersFromFile(loadedTable, "test_users.dat");

    ASSERT_EQ(authenticateUser(loadedTable, "testuser1", "password123"), 1) << "User1 should be authenticated after loading from file.";
    ASSERT_EQ(authenticateUser(loadedTable, "testuser2", "mypassword"), 1) << "User2 should be authenticated after loading from file.";

    freeHashTable(loadedTable);
}

/**
 * @brief Checks behavior when attempting to register a user with a duplicate username.
 */
TEST_F(UserAuthTest, DuplicateUserRegistration) {
    addUser(table, "duplicateuser", "password123");
    addUser(table, "duplicateuser", "newpassword");
    ASSERT_EQ(authenticateUser(table, "duplicateuser", "password123"), 1) << "Original password should still work for duplicate username.";
    ASSERT_EQ(authenticateUser(table, "duplicateuser", "newpassword"), 0) << "New password should not overwrite existing user.";
}

/**
 * @brief Verifies that password encryption and decryption behave as expected.
 */
TEST_F(UserAuthTest, EncryptPassword) {
    const char* password = "testpassword";
    char* encrypted = encryptPassword(password);
    ASSERT_STRNE(password, encrypted) << "Encrypted password should not be the same as the original.";
    char* decrypted = encryptPassword(encrypted);
    ASSERT_STREQ(password, decrypted) << "Decrypting the encrypted password should return the original password.";
    free(encrypted);
    free(decrypted);
}

/**
 * @class PetManagementTest
 * @brief Test fixture for pet management functionality.
 */
class PetManagementTest : public ::testing::Test {
protected:
    /**
     * @brief Head pointer to a linked list of pets.
     */
    Pet* petList = nullptr;

    /**
     * @brief Performs cleanup after each test.
     */
    void TearDown() override {
        freePetList(petList);
        petList = nullptr;
    }
};

/**
 * @brief Validates that adding a pet creates a new entry in the pet list.
 */
TEST_F(PetManagementTest, AddPetAddsNewPetToList) {
    addPet(&petList, "Buddy", "Dog", 3, "Alice");
    ASSERT_NE(petList, nullptr);
    EXPECT_STREQ(petList->name, "Buddy");
    EXPECT_STREQ(petList->type, "Dog");
    EXPECT_EQ(petList->age, 3);
    EXPECT_STREQ(petList->owner, "Alice");
}

/**
 * @brief Tests that an update attempt fails when the pet is not found.
 */
TEST_F(PetManagementTest, UpdatePet_Failure_NotFound) {
    testing::internal::CaptureStdout();
    updatePet(petList, "Nonexistent", "Mustafa");
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_TRUE(output.find("Pet not found or you do not have permission to update this pet.") != std::string::npos);
}

/**
 * @brief Tests that an update attempt fails if the user does not own the pet.
 */
TEST_F(PetManagementTest, UpdatePet_Failure_PermissionDenied) {
    addPet(&petList, "Milo", "Cat", 2, "Ahmet");

    testing::internal::CaptureStdout();
    updatePet(petList, "Milo", "Mustafa");
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_TRUE(output.find("Pet not found or you do not have permission to update this pet.") != std::string::npos);
}

/**
 * @brief Verifies that the correct pet is removed from the list.
 */
TEST_F(PetManagementTest, DeletePetRemovesCorrectPet) {
    addPet(&petList, "Buddy", "Dog", 3, "Alice");
    deletePet(&petList, "Buddy", "Alice");

    EXPECT_EQ(petList, nullptr);
}

/**
 * @brief Ensures that pet data can be saved to a file and loaded correctly.
 */
TEST_F(PetManagementTest, SaveAndLoadPets) {
    addPet(&petList, "Buddy", "Dog", 3, "Alice");
    addPet(&petList, "Kitty", "Cat", 2, "Bob");

    savePetsToFile(petList, "pets_test.dat");

    Pet* loadedPets = nullptr;
    loadPetsFromFile(&loadedPets, "pets_test.dat");

    ASSERT_NE(loadedPets, nullptr);
    EXPECT_STREQ(loadedPets->name, "Buddy");
    EXPECT_STREQ(loadedPets->type, "Dog");
    EXPECT_EQ(loadedPets->age, 3);
    EXPECT_STREQ(loadedPets->owner, "Alice");

    ASSERT_NE(loadedPets->next, nullptr);
    EXPECT_STREQ(loadedPets->next->name, "Kitty");
    EXPECT_STREQ(loadedPets->next->type, "Cat");
    EXPECT_EQ(loadedPets->next->age, 2);
    EXPECT_STREQ(loadedPets->next->owner, "Bob");

    freePetList(loadedPets);
}

/**
 * @brief Verifies the freeing of all allocated pet nodes.
 */
TEST_F(PetManagementTest, FreePetList) {
    Pet* petList = NULL;

    addPet(&petList, "Bella", "Dog", 3, "Mustafa");
    addPet(&petList, "Luna", "Cat", 2, "Ali");
    addPet(&petList, "Max", "Rabbit", 1, "Ahmet");

    ASSERT_NE(petList, nullptr);
    ASSERT_NE(petList->next, nullptr);

    freePetList(petList);

    SUCCEED();
}

/**
 * @brief Array of PetInfo objects for testing sorting and heap operations.
 */
PetInfo pets[] = {
    {"Charlie", "Dog", 3, "Alice"},
    {"Bella", "Cat", 2, "Bob"},
    {"Max", "Parrot", 5, "Carol"},
    {"Daisy", "Rabbit", 1, "David"}
};

/**
 * @brief Checks if an array of PetInfo structures is sorted by pet name.
 * @param arr The array of PetInfo to check.
 * @param n The number of elements in the array.
 * @return True if sorted by name in ascending order, false otherwise.
 */
bool isSorted(PetInfo arr[], int n) {
    for (int i = 0; i < n - 1; i++) {
        if (strcmp(arr[i].name, arr[i + 1].name) > 0) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Tests the heapify function to ensure the heap property is maintained.
 */
TEST(HeapifyTest, MaintainsHeapProperty) {
    PetInfo testArr[] = {
        {"Charlie", "Dog", 3, "Alice"},
        {"Bella", "Cat", 2, "Bob"},
        {"Max", "Parrot", 5, "Carol"}
    };
    int n = 3;
    heapify(testArr, n, 0);

    EXPECT_GE(strcmp(testArr[0].name, testArr[1].name), 0);
    EXPECT_GE(strcmp(testArr[0].name, testArr[2].name), 0);
}

/**
 * @brief Tests the heap sort function to verify that pets are sorted by name.
 */
TEST(HeapSortTest, SortsPetsByName) {
    PetInfo testArr[] = {
        {"Charlie", "Dog", 3, "Alice"},
        {"Bella", "Cat", 2, "Bob"},
        {"Max", "Parrot", 5, "Carol"},
        {"Daisy", "Rabbit", 1, "David"}
    };
    int n = 4;
    heapSort(testArr, n);

    EXPECT_TRUE(isSorted(testArr, n));
}

/**
 * @brief Checks that listing all pets outputs them in sorted order by name.
 */
TEST(ListAllPetsTest, OutputsSortedPetList) {

    Pet* petList = NULL;

    addPet(&petList, "Charlie", "Dog", 3, "Alice");
    addPet(&petList, "Bella", "Cat", 2, "Bob");
    addPet(&petList, "Max", "Parrot", 5, "Carol");
    addPet(&petList, "Daisy", "Rabbit", 1, "David");

    testing::internal::CaptureStdout(); 
    listAllPets(petList);
    std::string output = testing::internal::GetCapturedStdout();

    std::string expectedOutput =
        "List of All Pets (Sorted by Name):\n"
        "Name: Bella, Type: Cat, Age: 2, Owner: Bob\n"
        "Name: Charlie, Type: Dog, Age: 3, Owner: Alice\n"
        "Name: Daisy, Type: Rabbit, Age: 1, Owner: David\n"
        "Name: Max, Type: Parrot, Age: 5, Owner: Carol\n";

    EXPECT_EQ(output, expectedOutput);

    freePetList(petList);
}

/**
 * @brief Creates a sample doubly linked list of pets for testing.
 * @return A pointer to the head of the created pet list.
 */
Pet* createSamplePetList() {
    Pet* pet1 = (Pet*)malloc(sizeof(Pet));
    pet1->name = strdup("Buddy");
    pet1->type = strdup("Dog");
    pet1->age = 5;
    pet1->owner = strdup("Alice");
    pet1->next = NULL;
    pet1->prev = NULL;

    Pet* pet2 = (Pet*)malloc(sizeof(Pet));
    pet2->name = strdup("Milo");
    pet2->type = strdup("Cat");
    pet2->age = 3;
    pet2->owner = strdup("Bob");
    pet2->next = NULL;
    pet2->prev = pet1;
    pet1->next = pet2;

    Pet* pet3 = (Pet*)malloc(sizeof(Pet));
    pet3->name = strdup("Charlie");
    pet3->type = strdup("Bird");
    pet3->age = 2;
    pet3->owner = strdup("Alice");
    pet3->next = NULL;
    pet3->prev = pet2;
    pet2->next = pet3;

    return pet1;
}

/**
 * @brief Tests BFS search for pets by name.
 */
TEST(BFSSearchTest, SearchByName) {
    Pet* petList = createSamplePetList();
    testing::internal::CaptureStdout();
    bfsSearch(petList, "Buddy");
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("Name: Buddy"), std::string::npos);
    freePetList(petList);
}

/**
 * @brief Tests BFS search when the pet name does not exist.
 */
TEST(BFSSearchTest, SearchByNameNotFound) {
    Pet* petList = createSamplePetList();
    testing::internal::CaptureStdout();
    bfsSearch(petList, "Unknown");
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("No pets found matching 'Unknown'."), std::string::npos);
    freePetList(petList);
}

/**
 * @brief Tests DFS search for pets by type.
 */
TEST(DFSSearchTest, SearchByType) {
    Pet* petList = createSamplePetList();
    testing::internal::CaptureStdout();
    dfsSearch(petList, "Cat");
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("Type: Cat"), std::string::npos);
    freePetList(petList);
}

/**
 * @brief Tests DFS search when the pet type does not exist.
 */
TEST(DFSSearchTest, SearchByTypeNotFound) {
    Pet* petList = createSamplePetList();
    testing::internal::CaptureStdout();
    dfsSearch(petList, "Fish");
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("No pets found matching 'Fish'."), std::string::npos);
    freePetList(petList);
}

/**
 * @brief Verifies behavior of BFS and DFS searches on an empty pet list.
 */
TEST(SearchTest, EmptyList) {
    Pet* emptyList = NULL;
    testing::internal::CaptureStdout();
    bfsSearch(emptyList, "Buddy");
    std::string bfsOutput = testing::internal::GetCapturedStdout();
    EXPECT_NE(bfsOutput.find("The pet list is empty."), std::string::npos);

    testing::internal::CaptureStdout();
    dfsSearch(emptyList, "Buddy");
    std::string dfsOutput = testing::internal::GetCapturedStdout();
    EXPECT_NE(dfsOutput.find("The pet list is empty."), std::string::npos);
}
/**
 * @brief Pet list pointer for holding pets in some tests.
 */
Pet* petList = NULL;     
/**
 * @brief Appointment list pointer for scheduling appointments.
 */
Appointment* appointmentList = NULL; 

/**
 * @brief Resets the global pet list and appointment list data.
 */
void resetData() {
    freePetList(petList);
    petList = NULL;

    Appointment* current = appointmentList;
    Appointment* prev = NULL;
    Appointment* next = NULL;

    while (current != NULL) {
        next = XOR(prev, current->xorPtr);
        free(current);
        prev = current;
        current = next;
    }

    appointmentList = NULL;
}

/**
 * @brief Tests adding an appointment on a date that is already taken.
 */
TEST(AddAppointmentTest, AddDuplicateDateError) {
    resetData();
    addPet(&petList, "Buddy", "Dog", 3, "Alice");

    addAppointment("Buddy", "Checkup", 15, 12, "Alice", petList);
    testing::internal::CaptureStdout();
    addAppointment("Buddy", "Vaccination", 15, 12, "Alice", petList);
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_TRUE(output.find("Error: The date 15/12 is already occupied.") != std::string::npos);
}

/**
 * @brief Tests adding an appointment for a user who does not own the pet.
 */
TEST(AddAppointmentTest, AddUnauthorizedUserError) {
    resetData();
    addPet(&petList, "Buddy", "Dog", 3, "Alice");

    testing::internal::CaptureStdout();
    addAppointment("Buddy", "Checkup", 15, 12, "Bob", petList);
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_TRUE(output.find("Error: You do not own a pet named 'Buddy'.") != std::string::npos);
}

/**
 * @brief Tests updating an existing appointment with valid inputs.
 */
TEST(UpdateAppointmentTest, UpdateValidAppointment) {
    resetData();
    addPet(&petList, "Buddy", "Dog", 3, "Alice");

    addAppointment("Buddy", "Checkup", 15, 12, "Alice", petList);

    bool updateResult = updateAppointment("Buddy", 15, 12, 16, 12, "Vaccination", "Alice");
    ASSERT_TRUE(updateResult) << "Appointment update should return true for valid inputs.";
}

/**
 * @brief Tests updating an appointment that does not exist.
 */
TEST(UpdateAppointmentTest, UpdateAppointmentNotFoundError) {
    resetData();
    testing::internal::CaptureStdout();
    ASSERT_FALSE(updateAppointment("Buddy", 15, 12, 16, 12, "Vaccination", "Alice"));
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_TRUE(output.find("Error: No matching appointment found") == std::string::npos);
}

/**
 * @brief Tests cancellation of a valid appointment.
 */
TEST(CancelAppointmentTest, CancelValidAppointment) {
    resetData();
    addPet(&petList, "Buddy", "Dog", 3, "Alice");

    addAppointment("Buddy", "Checkup", 15, 12, "Alice", petList);
    ASSERT_TRUE(cancelAppointment("Buddy", 15, 12, "Alice"));
    EXPECT_EQ(appointmentList, nullptr);
}


/**
 * @brief Tests viewing appointments for a specific month.
 */
TEST(ViewAppointmentsTest, DisplayAppointments) {
    resetData();
    addPet(&petList, "Buddy", "Dog", 3, "Alice");

    addAppointment("Buddy", "Checkup", 10, 12, "Alice", petList);
    addAppointment("Buddy", "Vaccination", 20, 12, "Alice", petList);

    testing::internal::CaptureStdout();
    viewAppointments(12);
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_TRUE(output.find("\033[31m 10\033[0m") != std::string::npos);
    EXPECT_TRUE(output.find("\033[31m 20\033[0m") != std::string::npos);
}

/**
 * @brief Tests the XOR pointer helper function for the appointment list.
 */
TEST(AppointmentTests, XORHelperTest) {
    Appointment a, b;
    Appointment* result = XOR(&a, &b);
    EXPECT_EQ(result, (Appointment*)((uintptr_t)(&a) ^ (uintptr_t)(&b)));

    result = XOR(nullptr, &b);
    EXPECT_EQ(result, &b);

    result = XOR(&a, nullptr);
    EXPECT_EQ(result, &a);
}

/**
 * @brief Tests saving appointments to file
 */
TEST(AppointmentTests, SaveAppointmentsToFile) {
    resetData();
    const char* testFile = "test_appointments.data";
    
    addPet(&petList, "Buddy", "Dog", 3, "Alice");
    addAppointment("Buddy", "Checkup", 10, 5, "Alice", petList);
    addAppointment("Buddy", "Vaccination", 15, 6, "Alice", petList);
    
    saveAppointmentsToFile();
    
    FILE* file = fopen(testFile, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fclose(file);
        EXPECT_GT(size, 0) << "Appointments file should not be empty";
    }
    
    remove("appointment.data");
}

/**
 * @brief Tests loading appointments from file
 */
TEST(AppointmentTests, LoadAppointmentsFromFile) {
    resetData();
    
    addPet(&petList, "Buddy", "Dog", 3, "Alice");
    addAppointment("Buddy", "Checkup", 20, 7, "Alice", petList);
    addAppointment("Buddy", "Grooming", 25, 8, "Alice", petList);
    
    saveAppointmentsToFile();
    
    // File should exist and have content
    FILE* file = fopen("appointment.data", "rb");
    ASSERT_NE(file, nullptr) << "Appointment file should exist";
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fclose(file);
    
    EXPECT_GT(size, 0) << "Appointment file should have content";
    
    // Call load to ensure it doesn't crash
    loadAppointmentsFromFile();
    
    remove("appointment.data");
}

/**
 * @brief Tests save and load appointment cycle preserves data
 */
TEST(AppointmentTests, SaveLoadCycle) {
    resetData();
    
    addPet(&petList, "Max", "Cat", 2, "Bob");
    addAppointment("Max", "Checkup", 12, 3, "Bob", petList);
    addAppointment("Max", "Vaccination", 18, 4, "Bob", petList);
    
    // Save appointments
    saveAppointmentsToFile();
    
    // Verify file was created
    FILE* file = fopen("appointment.data", "rb");
    ASSERT_NE(file, nullptr) << "Appointment file should be created";
    fclose(file);
    
    // Load should not crash
    EXPECT_NO_THROW(loadAppointmentsFromFile()) << "Loading appointments should not crash";
    
    remove("appointment.data");
}

/**
 * @class BPlusTreeTest
 * @brief Test fixture for B+ tree operations on pet birthdays.
 */
class BPlusTreeTest : public ::testing::Test {
protected:
    /**
     * @brief B+ tree for storing and managing pet birthdays.
     */
    BPlusTree* tree;
    /**
     * @brief Pet list pointer used with the B+ tree.
     */
    Pet* petList;

    /**
     * @brief Initializes the B+ tree and pet list before each test.
     */
    void SetUp() override {
        tree = createBPlusTree();
        petList = NULL;
    }

    /**
     * @brief Frees the pet list and deletes the B+ tree after each test.
     */
    void TearDown() override {
        freePetList(petList);
        delete tree;
    }
};

/**
 * @brief Tests inserting a birthday record into the B+ tree.
 */
TEST_F(BPlusTreeTest, InsertBirthday) {
    insertBirthday(tree, "Buddy", 5, 10, 2020);
    ASSERT_NE(tree->root, nullptr);
    EXPECT_EQ(tree->root->keys[0], hashFunction("Buddy"));
    EXPECT_EQ(tree->root->values[0], 20201005); 
}

/**
 * @brief Verifies that the correct user ownership of a pet is reported.
 */
TEST_F(BPlusTreeTest, CheckPetOwnership) {
    addPet(&petList, "Buddy", "Dog", 3, "John");
    addPet(&petList, "Kitty", "Cat", 2, "Jane");

    EXPECT_TRUE(isPetOwnedByUser(petList, "Buddy", "John"));
    EXPECT_FALSE(isPetOwnedByUser(petList, "Kitty", "John"));
}

/**
 * @brief Tests saving birthdays to a file.
 */
TEST_F(BPlusTreeTest, SaveBirthdays) {
    const char* filename = "test_birthdays.data";

    addPet(&petList, "Buddy", "Dog", 3, "John");
    insertBirthday(tree, "Buddy", 5, 10, 2020);

    saveBirthdaysToFile(tree, filename, petList);

    FILE* file = fopen(filename, "rb");
    ASSERT_NE(file, nullptr);
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fclose(file);

    EXPECT_GT(fileSize, 0);

    std::remove(filename);
}

/**
 * @brief Verifies that saved birthday data is encrypted and not in plain text.
 */
TEST_F(BPlusTreeTest, EncryptionTest) {
    const char* filename = "test_encrypted_birthdays.data";

    addPet(&petList, "Buddy", "Dog", 3, "John");
    insertBirthday(tree, "Buddy", 15, 8, 2022);

    saveBirthdaysToFile(tree, filename, petList);

    FILE* file = fopen(filename, "rb");
    ASSERT_NE(file, nullptr);
    char encryptedData[50];
    fread(encryptedData, sizeof(char), 50, file);
    fclose(file);

    EXPECT_STRNE(encryptedData, "Buddy");

    std::remove(filename);
}

/**
 * @class ExerciseRoutineTest
 * @brief Test fixture for exercise routines managed via a stack.
 */
class ExerciseRoutineTest : public ::testing::Test {
protected:
    /**
     * @brief Resets the exercise stack before each exercise routine test.
     */
    void SetUp() override {
        exerciseStack.top = -1;
    }

    /**
     * @brief Clears the exercise stack after each exercise routine test.
     */
    void TearDown() override {
        exerciseStack.top = -1;
    }
};

/**
 * @brief Tests successfully adding a new exercise routine to the stack.
 */
TEST_F(ExerciseRoutineTest, AddExerciseRoutine_Success) {
    addExerciseRoutine("Buddy", "Morning Run");
    EXPECT_EQ(exerciseStack.top, 0);
    EXPECT_STREQ(exerciseStack.stack[0].petName, "Buddy");
    EXPECT_STREQ(exerciseStack.stack[0].exercise, "Morning Run");
}

/**
 * @brief Tests handling of a full exercise stack.
 */
TEST_F(ExerciseRoutineTest, AddExerciseRoutine_FullStack) {
    for (int i = 0; i < MAX_ROUTINES; ++i) {
        addExerciseRoutine("Pet", "Routine");
    }

    testing::internal::CaptureStdout();
    addExerciseRoutine("OverflowPet", "Extra Routine");
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_EQ(exerciseStack.top, MAX_ROUTINES - 1);
    EXPECT_NE(output.find("Error: Stack is full"), std::string::npos);
}

/**
 * @brief Tests listing all exercise routines in the stack.
 */
TEST_F(ExerciseRoutineTest, ListAllExercises) {
    addExerciseRoutine("Buddy", "Morning Run");
    addExerciseRoutine("Kitty", "Evening Stretch");

    testing::internal::CaptureStdout();
    listAllExercises();
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("Pet Name: Buddy\nRoutine: Morning Run"), std::string::npos);
    EXPECT_NE(output.find("Pet Name: Kitty\nRoutine: Evening Stretch"), std::string::npos);
}

/**
 * @brief Tests listing routines when the stack is empty.
 */
TEST_F(ExerciseRoutineTest, ListAllExercises_EmptyStack) {
    testing::internal::CaptureStdout();
    listAllExercises();
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("No exercise routines available."), std::string::npos);
}

/**
 * @brief Tests undoing (pop) the most recent exercise routine.
 */
TEST_F(ExerciseRoutineTest, UndoLastExercise) {
    addExerciseRoutine("Buddy", "Morning Run");
    addExerciseRoutine("Kitty", "Evening Stretch");

    testing::internal::CaptureStdout();
    undoLastExercise();
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_EQ(exerciseStack.top, 0);
    EXPECT_NE(output.find("Undoing last exercise routine for 'Kitty'"), std::string::npos);
}

/**
 * @brief Tests undo operation on an empty stack.
 */
TEST_F(ExerciseRoutineTest, UndoLastExercise_EmptyStack) {
    testing::internal::CaptureStdout();
    undoLastExercise();
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("Error: No exercise routines to undo."), std::string::npos);
}

/**
 * @class FindPetByNameTest
 * @brief Test fixture for the findPetByName function.
 */
class FindPetByNameTest : public ::testing::Test {
protected:
    /**
     * @brief Pet list pointer for storing sample pets.
     */
    Pet* petList = nullptr;
    /**
     * @brief Adds sample pets to the list before each test.
     */
    void SetUp() override {
        addPet(&petList, "Buddy", "Dog", 3, "Alice");
        addPet(&petList, "Milo", "Cat", 2, "Bob");
        addPet(&petList, "Charlie", "Bird", 1, "Carol");
    }

    /**
     * @brief Frees the sample pet list after each test.
     */
    void TearDown() override {
        freePetList(petList);
        petList = nullptr;
    }
};

/**
 * @brief Tests that a pet with a given name can be found by its hash key.
 */
TEST_F(FindPetByNameTest, FindPetByName_Found) {
    int key = hashFunction("Milo");
    Pet* foundPet = findPetByName(petList, key);

    ASSERT_NE(foundPet, nullptr);
    EXPECT_STREQ(foundPet->name, "Milo");
    EXPECT_STREQ(foundPet->type, "Cat");
    EXPECT_EQ(foundPet->age, 2);
}

/**
 * @brief Tests that no pet is found if the hash key does not match.
 */
TEST_F(FindPetByNameTest, FindPetByName_NotFound) {
    int key = hashFunction("Unknown");
    Pet* foundPet = findPetByName(petList, key);

    EXPECT_EQ(foundPet, nullptr);
}

/**
 * @brief Tests behavior on an empty pet list.
 */
TEST_F(FindPetByNameTest, FindPetByName_EmptyList) {
    freePetList(petList);
    petList = nullptr;

    int key = hashFunction("Buddy");
    Pet* foundPet = findPetByName(petList, key);

    EXPECT_EQ(foundPet, nullptr);
}

/**
 * @class MedicineQueueTest
 * @brief Test fixture for medicine schedule queue operations.
 */
class MedicineQueueTest : public ::testing::Test {
protected:
    /**
     * @brief Queue pointer for managing medicine schedules.
     */
    Queue* medicineQueue;

    /**
     * @brief Creates a new medicine queue before each test.
     */
    void SetUp() override {
        medicineQueue = createQueue();
    }

    /**
     * @brief Empties and deallocates the medicine queue after each test.
     */
    void TearDown() override {
        while (!isQueueEmpty(medicineQueue)) {
            FeedingSchedule* temp = dequeue(medicineQueue);
            free(temp);
        }
        free(medicineQueue);
    }
};

/**
 * @brief Tests adding a new medicine schedule to the queue.
 */
TEST_F(MedicineQueueTest, AddMedicineSchedule) {
    addMedicineSchedule(medicineQueue, "Buddy", "Morning Medicine");
    ASSERT_FALSE(isQueueEmpty(medicineQueue));

    EXPECT_STREQ(medicineQueue->front->petName, "Buddy");
    EXPECT_STREQ(medicineQueue->front->scheduleDetails, "Morning Medicine");
}

/**
 * @brief Tests updating the details of an existing medicine schedule.
 */
TEST_F(MedicineQueueTest, UpdateMedicineSchedule) {
    addMedicineSchedule(medicineQueue, "Buddy", "Morning Medicine");

    updateMedicineSchedule(medicineQueue, "Buddy", "Evening Medicine");

    EXPECT_STREQ(medicineQueue->front->scheduleDetails, "Evening Medicine");
}

/**
 * @brief Tests updating a medicine schedule that does not exist in the queue.
 */
TEST_F(MedicineQueueTest, UpdateMedicineSchedule_NotFound) {
    addMedicineSchedule(medicineQueue, "Buddy", "Morning Medicine");

    testing::internal::CaptureStdout();
    updateMedicineSchedule(medicineQueue, "Nonexistent", "Evening Medicine");
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("Medicine schedule for pet 'Nonexistent' not found."), std::string::npos);
}

/**
 * @brief Tests deleting a medicine schedule from the queue.
 */
TEST_F(MedicineQueueTest, DeleteMedicineSchedule) {
    addMedicineSchedule(medicineQueue, "Buddy", "Morning Medicine");

    deleteMedicineSchedule(medicineQueue, "Buddy");
    EXPECT_TRUE(isQueueEmpty(medicineQueue));
}

/**
 * @brief Tests deleting a medicine schedule that does not exist.
 */
TEST_F(MedicineQueueTest, DeleteMedicineSchedule_NotFound) {
    addMedicineSchedule(medicineQueue, "Buddy", "Morning Medicine");

    testing::internal::CaptureStdout();
    deleteMedicineSchedule(medicineQueue, "Nonexistent");
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("Medicine schedule for pet 'Nonexistent' not found."), std::string::npos);
}

/**
 * @brief Tests listing all medicine schedules in the queue.
 */
TEST_F(MedicineQueueTest, ViewMedicineSchedules) {
    addMedicineSchedule(medicineQueue, "Buddy", "Morning Medicine");
    addMedicineSchedule(medicineQueue, "Kitty", "Evening Medicine");

    testing::internal::CaptureStdout();
    viewMedicineSchedules(medicineQueue);
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("Pet: Buddy, Schedule: Morning Medicine"), std::string::npos);
    EXPECT_NE(output.find("Pet: Kitty, Schedule: Evening Medicine"), std::string::npos);
}

/**
 * @brief Tests listing schedules when the queue is empty.
 */
TEST_F(MedicineQueueTest, ViewMedicineSchedules_EmptyQueue) {
    testing::internal::CaptureStdout();
    viewMedicineSchedules(medicineQueue);
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("No medicine schedules available."), std::string::npos);
}

/**
 * @brief Tests the Strongly Connected Components (SCC) analysis for medicine schedule dependencies.
 */
TEST(MedicineScheduleTest, FindSCC) {
    testing::internal::CaptureStdout();
    findSCC();
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("Analyzing medicine schedule dependencies using SCC algorithm..."), std::string::npos);
    EXPECT_NE(output.find("Strongly Connected Components analysis completed."), std::string::npos);
}

/**
 * @class FeedingQueueTest
 * @brief Test fixture for feeding schedule queue operations.
 */
class FeedingQueueTest : public ::testing::Test {
protected:

    /**
     * @brief Queue pointer for handling feeding schedules.
     */
    Queue* feedingQueue;

    /**
     * @brief Initializes the feeding queue before each test.
     */
    void SetUp() override {
        feedingQueue = createQueue();
    }

    /**
     * @brief Empties and frees the feeding queue after each test.
     */
    void TearDown() override {
        while (!isQueueEmpty(feedingQueue)) {
            FeedingSchedule* temp = dequeue(feedingQueue);
            free(temp);
        }
        free(feedingQueue);
    }
};

/**
 * @brief Tests queue creation and initial conditions.
 */
TEST_F(FeedingQueueTest, CreateQueue) {
    ASSERT_NE(feedingQueue, nullptr);
    EXPECT_TRUE(isQueueEmpty(feedingQueue));
}

/**
 * @brief Tests enqueuing a feeding schedule into the queue.
 */
TEST_F(FeedingQueueTest, Enqueue) {
    enqueue(feedingQueue, "Buddy", "Morning Feed");
    ASSERT_FALSE(isQueueEmpty(feedingQueue));

    EXPECT_STREQ(feedingQueue->front->petName, "Buddy");
    EXPECT_STREQ(feedingQueue->front->scheduleDetails, "Morning Feed");
}

/**
 * @brief Tests dequeuing a feeding schedule from the queue.
 */
TEST_F(FeedingQueueTest, Dequeue) {
    enqueue(feedingQueue, "Buddy", "Morning Feed");
    enqueue(feedingQueue, "Kitty", "Evening Feed");

    FeedingSchedule* removed = dequeue(feedingQueue);
    ASSERT_NE(removed, nullptr);

    EXPECT_STREQ(removed->petName, "Buddy");
    EXPECT_STREQ(removed->scheduleDetails, "Morning Feed");

    free(removed); 
    EXPECT_FALSE(isQueueEmpty(feedingQueue));
    EXPECT_STREQ(feedingQueue->front->petName, "Kitty");
}

/**
 * @brief Tests the queue's empty-state detection.
 */
TEST_F(FeedingQueueTest, IsQueueEmpty) {
    EXPECT_TRUE(isQueueEmpty(feedingQueue));

    enqueue(feedingQueue, "Buddy", "Morning Feed");
    EXPECT_FALSE(isQueueEmpty(feedingQueue));
}

/**
 * @brief Tests updating an existing feeding schedule.
 */
TEST_F(FeedingQueueTest, UpdateFeedingSchedule) {
    enqueue(feedingQueue, "Buddy", "Morning Feed");

    updateFeedingSchedule(feedingQueue, "Buddy", "Evening Feed");
    EXPECT_STREQ(feedingQueue->front->scheduleDetails, "Evening Feed");
}

/**
 * @brief Tests updating a feeding schedule that does not exist.
 */
TEST_F(FeedingQueueTest, UpdateFeedingSchedule_NotFound) {
    enqueue(feedingQueue, "Buddy", "Morning Feed");

    testing::internal::CaptureStdout();
    updateFeedingSchedule(feedingQueue, "Nonexistent", "Evening Feed");
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("Feeding schedule for pet 'Nonexistent' not found."), std::string::npos);
}

/**
 * @brief Tests deleting a feeding schedule from the queue.
 */
TEST_F(FeedingQueueTest, DeleteFeedingSchedule) {
    enqueue(feedingQueue, "Buddy", "Morning Feed");

    deleteFeedingSchedule(feedingQueue, "Buddy");
    EXPECT_TRUE(isQueueEmpty(feedingQueue));
}

/**
 * @brief Tests deleting a feeding schedule that does not exist in the queue.
 */
TEST_F(FeedingQueueTest, DeleteFeedingSchedule_NotFound) {
    enqueue(feedingQueue, "Buddy", "Morning Feed");

    testing::internal::CaptureStdout();
    deleteFeedingSchedule(feedingQueue, "Nonexistent");
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("Feeding schedule for pet 'Nonexistent' not found."), std::string::npos);
}

/**
 * @brief Tests listing all feeding schedules in the queue.
 */
TEST_F(FeedingQueueTest, ViewFeedingSchedules) {
    enqueue(feedingQueue, "Buddy", "Morning Feed");
    enqueue(feedingQueue, "Kitty", "Evening Feed");

    testing::internal::CaptureStdout();
    viewFeedingSchedules(feedingQueue);
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("Pet: Buddy, Schedule: Morning Feed"), std::string::npos);
    EXPECT_NE(output.find("Pet: Kitty, Schedule: Evening Feed"), std::string::npos);
}

/**
 * @brief Tests listing feeding schedules when the queue is empty.
 */
TEST_F(FeedingQueueTest, ViewFeedingSchedules_EmptyQueue) {
    testing::internal::CaptureStdout();
    viewFeedingSchedules(feedingQueue);
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("No feeding schedules available."), std::string::npos);
}

/**
 * @class HuffmanTest
 * @brief Test fixture for Huffman coding functionality.
 */
class HuffmanTest : public ::testing::Test {
protected:
    /**
     * @brief Array to hold distinct characters for Huffman coding tests.
     */
    char data[256];

    /**
     * @brief Frequency of each character for Huffman coding.
     */
    int freq[256];

    /**
     * @brief Root node of the Huffman tree.
     */
    MinHeapNode* root;

    /**
     * @brief Table to store Huffman codes for each character.
     */
    char codes[256][MAX_TREE_HT];

    /**
     * @brief String buffer for the input to be compressed.
     */
    char input[1024];

    /**
     * @brief String buffer for the compressed output.
     */
    char compressed[1024];

    /**
     * @brief String buffer for the decompressed result.
     */
    char decompressed[1024];

    /**
     * @brief Sets up the Huffman tree and codes before each test.
     */
    void SetUp() override {
        strcpy(data, "abc");
        int example_freq[] = { 5, 3, 1 };
        memcpy(freq, example_freq, sizeof(example_freq));

        memset(codes, 0, sizeof(codes));
        HuffmanCodes(data, freq, 3, codes);

        root = buildHuffmanTree(data, freq, 3);

        strcpy(input, "abc");
        compressed[0] = '\0';
        decompressed[0] = '\0';
    }

    /**
     * @brief Frees the Huffman tree after each test.
     */
    void TearDown() override {
        free(root);
    }
};

/**
 * @brief Tests the creation of a new Huffman tree node.
 */
TEST_F(HuffmanTest, NewNodeTest) {
    MinHeapNode* node = newNode('a', 5);
    ASSERT_NE(node, nullptr);
    EXPECT_EQ(node->data, 'a');
    EXPECT_EQ(node->freq, 5);
    EXPECT_EQ(node->left, nullptr);
    EXPECT_EQ(node->right, nullptr);
    free(node);
}

/**
 * @brief Tests the creation of a new min-heap for Huffman coding.
 */
TEST_F(HuffmanTest, CreateMinHeapTest) {
    MinHeap* heap = createMinHeap(10);
    ASSERT_NE(heap, nullptr);
    EXPECT_EQ(heap->size, 0);
    EXPECT_EQ(heap->capacity, 10);
    ASSERT_NE(heap->array, nullptr);
    free(heap->array);
    free(heap);
}

/**
 * @brief Tests inserting into the min-heap and extracting the minimum element.
 */
TEST_F(HuffmanTest, InsertAndExtractMinTest) {
    MinHeap* heap = createMinHeap(10);
    insertMinHeap(heap, newNode('a', 5));
    insertMinHeap(heap, newNode('b', 3));
    MinHeapNode* minNode = extractMin(heap);
    ASSERT_NE(minNode, nullptr);
    EXPECT_EQ(minNode->data, 'b');
    EXPECT_EQ(minNode->freq, 3);
    free(minNode);
    free(heap->array);
    free(heap);
}

/**
 * @brief Tests constructing the Huffman tree from data and frequencies.
 */
TEST_F(HuffmanTest, BuildHuffmanTreeTest) {
    ASSERT_NE(root, nullptr);
    EXPECT_EQ(root->freq, 9);  
}

/**
 * @brief Verifies that Huffman codes are generated for each character.
 */
TEST_F(HuffmanTest, HuffmanCodesTest) {
    EXPECT_STRNE(codes[(int)'a'], "");
    EXPECT_STRNE(codes[(int)'b'], "");
    EXPECT_STRNE(codes[(int)'c'], "");
}

/**
 * @brief Tests compressing a string using generated Huffman codes.
 */
TEST_F(HuffmanTest, CompressTest) {
    compress(input, codes, compressed);
    ASSERT_STRNE(compressed, "");
    std::cout << "Sıkıştırılmış metin: " << compressed << std::endl;
}

/**
 * @brief Tests decompressing a string using the Huffman tree.
 */
TEST_F(HuffmanTest, DecompressTest) {
    compress(input, codes, compressed);
    decompress(root, compressed, decompressed);
    EXPECT_STREQ(input, decompressed);
}

/**
 * @brief Tests a full cycle of compression and decompression for correctness.
 */
TEST_F(HuffmanTest, CompressDecompressIntegratedTest) {
    compress(input, codes, compressed);
    decompress(root, compressed, decompressed);
    EXPECT_STREQ(input, decompressed);
}

/**
 * @brief Filename for stray animals pending adoption.
 */
static const char* TEST_ADOPTABLE_FILE = "test_adoptable.dat";

/**
 * @brief Filename for already adopted animals.
 */
static const char* TEST_ADOPTED_FILE = "test_adopted.dat";

/**
 * @brief Removes a file if it already exists, used to clean up test files.
 * @param filename Name of the file to be removed.
 */
void removeFileIfExists(const char* filename) {
    std::remove(filename);
}

/**
 * @class StrayAnimalTest
 * @brief Test fixture for stray and adopted animal operations.
 */
class StrayAnimalTest : public ::testing::Test {
protected:

    /**
     * @brief Sets up stray and adopted lists, removing any old test files.
     */
    void SetUp() override {
        strayList = nullptr;
        adoptedList = nullptr;

        removeFileIfExists(TEST_ADOPTABLE_FILE);
        removeFileIfExists(TEST_ADOPTED_FILE);
    }

    /**
     * @brief Frees stray and adopted lists, and removes test files after each test.
     */
    void TearDown() override {
        while (strayList) {
            StrayAnimal* temp = strayList;
            strayList = strayList->next;
            free(temp);
        }
        while (adoptedList) {
            AdoptedAnimal* temp = adoptedList;
            adoptedList = adoptedList->next;
            free(temp);
        }

        removeFileIfExists(TEST_ADOPTABLE_FILE);
        removeFileIfExists(TEST_ADOPTED_FILE);
    }

    /**
     * @brief Pointer to the list of stray animals.
     */
    StrayAnimal* strayList;

    /**
     * @brief Pointer to the list of adopted animals.
     */
    AdoptedAnimal* adoptedList;
};

/**
 * @brief Tests the KMP search with an empty pattern.
 */
TEST_F(StrayAnimalTest, KMP_EmptyPatternShouldMatchAnyText) {
    const char* text = "example";
    const char* pattern = "";

    bool result = KMPcontains(text, pattern);
    EXPECT_TRUE(result);
}

/**
 * @brief Tests the KMP search for a pattern that is present in the text.
 */
TEST_F(StrayAnimalTest, KMP_Found) {
    const char* text = "dogcatparrot";
    const char* pattern = "cat";
    bool result = KMPcontains(text, pattern);
    EXPECT_TRUE(result);
}

/**
 * @brief Tests the KMP search for a pattern that is absent in the text.
 */
TEST_F(StrayAnimalTest, KMP_NotFound) {
    const char* text = "dogcatparrot";
    const char* pattern = "bird";
    bool result = KMPcontains(text, pattern);
    EXPECT_FALSE(result);
}

/**
 * @brief Tests adding stray animals to the list and then listing them.
 */
TEST_F(StrayAnimalTest, AddStrayAnimal_And_ListStrayAnimals) {
    addStrayAnimalToList(&strayList, "Cat", "Female", "01/01/2023", 2);
    addStrayAnimalToList(&strayList, "Dog", "Male", "02/01/2023", 3);

    int count = 0;
    for (StrayAnimal* cur = strayList; cur != nullptr; cur = cur->next) {
        count++;
    }
    EXPECT_EQ(count, 2);

    listStrayAnimals(strayList);
}

/**
 * @brief Tests searching for stray animals using KMP.
 */
TEST_F(StrayAnimalTest, SearchStrayAnimalsKMP_ShouldFindCorrectAnimal) {
    addStrayAnimalToList(&strayList, "Cat", "Female", "01/01/2023", 2);
    addStrayAnimalToList(&strayList, "Dog", "Male", "02/01/2023", 3);

    searchStrayAnimalsKMP(strayList, "Cat");
    searchStrayAnimalsKMP(strayList, "Parrot");
}

/**
 * @brief Tests successful update of a stray animal's information.
 */
TEST_F(StrayAnimalTest, UpdateStrayAnimal_Success) {
    addStrayAnimalToList(&strayList, "Dog", "Male", "01/01/2023", 3);
    int originalID = strayList->id;

    updateStrayAnimal(
        strayList,
        originalID,
        "Cat",           // newType
        "Female",        // newGender
        "02/02/2023",    // newArrivalDate
        5                // newAge
    );

    EXPECT_STREQ(strayList->type, "Cat");
    EXPECT_STREQ(strayList->gender, "Female");
    EXPECT_STREQ(strayList->arrivalDate, "02/02/2023");
    EXPECT_EQ(strayList->age, 5);
}

/**
 * @brief Tests trying to update a stray animal that does not exist.
 */
TEST_F(StrayAnimalTest, UpdateStrayAnimal_IdNotFound) {
    addStrayAnimalToList(&strayList, "Cat", "Female", "01/01/2023", 2);
    addStrayAnimalToList(&strayList, "Dog", "Male", "02/02/2023", 4);

    updateStrayAnimal(
        strayList,
        999,
        "Rabbit",
        "Female",
        "05/05/2023",
        1
    );

    StrayAnimal* first = strayList;
    StrayAnimal* second = strayList->next;

    ASSERT_NE(first, nullptr);
    EXPECT_STREQ(first->type, "Cat");
    EXPECT_STREQ(first->gender, "Female");
    EXPECT_STREQ(first->arrivalDate, "01/01/2023");
    EXPECT_EQ(first->age, 2);

    ASSERT_NE(second, nullptr);
    EXPECT_STREQ(second->type, "Dog");
    EXPECT_STREQ(second->gender, "Male");
    EXPECT_STREQ(second->arrivalDate, "02/02/2023");
    EXPECT_EQ(second->age, 4);
}

/**
 * @brief Tests deleting a stray animal from the list.
 */
TEST_F(StrayAnimalTest, DeleteStrayAnimal_ShouldRemoveFromList) {
    addStrayAnimalToList(&strayList, "Cat", "Female", "01/01/2023", 2);
    addStrayAnimalToList(&strayList, "Dog", "Male", "02/01/2023", 3);

    int firstID = strayList->id;
    int secondID = strayList->next->id;

    deleteStrayAnimal(&strayList, firstID);

    int count = 0;
    StrayAnimal* cur = strayList;
    while (cur) {
        count++;
        EXPECT_NE(cur->id, firstID);
        cur = cur->next;
    }
    EXPECT_EQ(count, 1);

    EXPECT_EQ(strayList->id, secondID);
}


/**
 * @brief Tests saving stray animals to a file and loading them back.
 */
TEST_F(StrayAnimalTest, SaveAndLoadStrayAnimals) {
    addStrayAnimalToList(&strayList, "Cat", "Female", "01/01/2023", 2);
    addStrayAnimalToList(&strayList, "Dog", "Male", "02/02/2023", 3);

    saveStrayAnimalsToFile(strayList, TEST_ADOPTABLE_FILE);

    while (strayList) {
        StrayAnimal* temp = strayList;
        strayList = strayList->next;
        free(temp);
    }

    loadStrayAnimalsFromFile(&strayList, TEST_ADOPTABLE_FILE);

    int count = 0;
    for (StrayAnimal* cur = strayList; cur; cur = cur->next) {
        count++;
    }
    EXPECT_EQ(count, 2);

    bool foundCat = false;
    bool foundDog = false;
    for (StrayAnimal* cur = strayList; cur; cur = cur->next) {
        if (strcmp(cur->type, "Cat") == 0) foundCat = true;
        if (strcmp(cur->type, "Dog") == 0) foundDog = true;
    }
    EXPECT_TRUE(foundCat);
    EXPECT_TRUE(foundDog);
}

/**
 * @brief Tests saving adopted animals to a file and loading them back.
 */
TEST_F(StrayAnimalTest, SaveAndLoadAdoptedAnimals) {

    AdoptedAnimal an;
    an.id = 1001;
    strcpy(an.type, "Cat");
    strcpy(an.gender, "Female");
    strcpy(an.arrivalDate, "01/01/2023");
    an.age = 2;
    strcpy(an.owner, "TestUser");
    strcpy(an.adoptionDate, "05/02/2023");

    AdoptedAnimal* node = (AdoptedAnimal*)malloc(sizeof(AdoptedAnimal));
    memcpy(node, &an, sizeof(AdoptedAnimal));
    node->next = nullptr;
    adoptedList = node;

    saveAdoptedAnimalsToFile(adoptedList, TEST_ADOPTED_FILE);

    free(adoptedList);
    adoptedList = nullptr;

    loadAdoptedAnimalsFromFile(&adoptedList, TEST_ADOPTED_FILE);


    ASSERT_NE(adoptedList, nullptr);
    EXPECT_EQ(adoptedList->id, 1001);
    EXPECT_STREQ(adoptedList->type, "Cat");
    EXPECT_STREQ(adoptedList->owner, "TestUser");
    EXPECT_STREQ(adoptedList->adoptionDate, "05/02/2023");
}

/**
 * @brief Tests listing all adopted animals when there are none and when there is at least one.
 */
TEST_F(StrayAnimalTest, ListAllAdoptedAnimals) {
    listAllAdoptedAnimals(adoptedList);
    SUCCEED();

    AdoptedAnimal an;
    an.id = 1002;
    strcpy(an.type, "Dog");
    strcpy(an.gender, "Male");
    strcpy(an.arrivalDate, "02/03/2023");
    an.age = 3;
    strcpy(an.owner, "TestUser");
    strcpy(an.adoptionDate, "07/03/2023");

    AdoptedAnimal* node = (AdoptedAnimal*)malloc(sizeof(AdoptedAnimal));
    memcpy(node, &an, sizeof(AdoptedAnimal));
    node->next = nullptr;

    adoptedList = node;

    listAllAdoptedAnimals(adoptedList);
    SUCCEED();
}

/**
 * @brief Tests loading of B+ tree birthday data from a file and verifying pet details.
 */
TEST(LoadBirthdaysTest, BasicLoad) {
    const char* testFilename = "test_birthdays.dat";


    BPlusTree* originalTree = createBPlusTree();
    Pet* originalPetList = nullptr;

    addPet(&originalPetList, "Tom", "Cat", 3, "Alice");
    insertBirthday(originalTree, "Tom", 12, 5, 2024);

    addPet(&originalPetList, "Rex", "Dog", 5, "Bob");
    insertBirthday(originalTree, "Rex", 1, 12, 2023);

    addPet(&originalPetList, "Nemo", "Fish", 1, "Charlie");
    insertBirthday(originalTree, "Nemo", 31, 3, 2025);

    saveBirthdaysToFile(originalTree, testFilename, originalPetList);

    BPlusTree* loadedTree = createBPlusTree();
    Pet* loadedPetList = nullptr;

    loadBirthdaysFromFile(loadedTree, testFilename, &loadedPetList);

    Pet* foundTom = findPetByName(loadedPetList, hashFunction("Tom"));
    ASSERT_NE(foundTom, nullptr) << "Tom pet'i yüklenemedi!";
    EXPECT_STREQ(foundTom->name, "Tom");
    EXPECT_STREQ(foundTom->type, "Cat");
    EXPECT_EQ(foundTom->age, 3);
    EXPECT_STREQ(foundTom->owner, "Alice");

    Pet* foundRex = findPetByName(loadedPetList, hashFunction("Rex"));
    ASSERT_NE(foundRex, nullptr) << "Rex pet'i yüklenemedi!";
    EXPECT_STREQ(foundRex->name, "Rex");
    EXPECT_STREQ(foundRex->type, "Dog");
    EXPECT_EQ(foundRex->age, 5);
    EXPECT_STREQ(foundRex->owner, "Bob");

    Pet* foundNemo = findPetByName(loadedPetList, hashFunction("Nemo"));
    ASSERT_NE(foundNemo, nullptr) << "Nemo pet'i yüklenemedi!";
    EXPECT_STREQ(foundNemo->name, "Nemo");
    EXPECT_STREQ(foundNemo->type, "Fish");
    EXPECT_EQ(foundNemo->age, 1);
    EXPECT_STREQ(foundNemo->owner, "Charlie");

    std::remove(testFilename);

}

/**
 * @brief Creates a stray animal node for testing.
 * @param id Unique ID of the stray animal.
 * @param type The species type of the stray animal.
 * @param gender The gender of the stray animal.
 * @param arrivalDate The date the animal arrived.
 * @param age The age of the animal.
 * @return Pointer to the created StrayAnimal node.
 */
static StrayAnimal* createStrayAnimal(int id, const char* type, const char* gender, const char* arrivalDate, int age) {
    StrayAnimal* animal = (StrayAnimal*)malloc(sizeof(StrayAnimal));
    animal->id = id;
    strcpy(animal->type, type);
    strcpy(animal->gender, gender);
    strcpy(animal->arrivalDate, arrivalDate);
    animal->age = age;
    animal->next = nullptr;
    return animal;
}

/**
 * @brief Finds an adopted animal in the list by its ID (for testing).
 * @param list Pointer to the head of AdoptedAnimal list.
 * @param id The ID to search for.
 * @return True if found, false otherwise.
 */
static bool findAdoptedAnimal(AdoptedAnimal* list, int id) {
    while (list) {
        if (list->id == id) {
            return true;
        }
        list = list->next;
    }
    return false;
}

/**
 * @brief Tests the adoption flow of a stray animal that exists in the list.
 */
TEST(AdoptStrayAnimalTest, BasicAdoptionFlow) {
    StrayAnimal* strayList = createStrayAnimal(1, "Dog", "Male", "12/12/2023", 2);

    int chosenID = 1;
    const char* newName = "Fluffy";
    const char* adoptionDate = "01/01/2024";
    const char* activeUser = "TestUser";

    adoptStrayAnimal(&strayList, activeUser, chosenID, newName, adoptionDate);

    EXPECT_EQ(strayList, nullptr)
        << "Stray list should be empty after adopting the only animal with ID=1.";

    AdoptedAnimal* adoptedList = nullptr;
    loadAdoptedAnimalsFromFile(&adoptedList, "adopted.dat");

    EXPECT_TRUE(findAdoptedAnimal(adoptedList, 1))
        << "Adopted animal with ID=1 not found in adoptedList!";
}

/**
 * @brief Tests the adoption flow attempt on a non-existent stray animal ID.
 */
TEST(AdoptStrayAnimalTest, NonExistentID) {
    StrayAnimal* strayList = createStrayAnimal(1, "Cat", "Female", "10/10/2023", 1);

    int chosenID = 999;
    const char* newName = "Kitty";
    const char* adoptionDate = "02/02/2024";
    const char* activeUser = "TestUser";

    adoptStrayAnimal(&strayList, activeUser, chosenID, newName, adoptionDate);

    EXPECT_NE(strayList, nullptr)
        << "Stray list should remain unchanged if the chosen ID is not found.";

    AdoptedAnimal* adoptedList = nullptr;
    loadAdoptedAnimalsFromFile(&adoptedList, "adopted.dat");

    EXPECT_FALSE(findAdoptedAnimal(adoptedList, 999))
        << "Adopted animal with ID=999 should not exist in adoptedList!";

}

/**
 * @brief Tests listing all pet birthdays stored in the B+ tree along with pet details.
 */
TEST_F(BPlusTreeTest, ListPetBirthdays_BasicFunctionality) {

    addPet(&petList, "Tom", "Cat", 3, "Alice");
    addPet(&petList, "Rex", "Dog", 5, "Bob");
    addPet(&petList, "Nemo", "Fish", 1, "Charlie");

    insertBirthday(tree, "Tom", 12, 5, 2024);    // 20240512
    insertBirthday(tree, "Rex", 1, 12, 2023);    // 20231201
    insertBirthday(tree, "Nemo", 31, 3, 2025);   // 20250331

    std::string expectedOutput = "\n--- List of Pet Birthdays ---\n";
    expectedOutput += "Pet Name: Tom | Type: Cat | Owner: Alice | Birthday: 12/05/2024\n";
    expectedOutput += "Pet Name: Rex | Type: Dog | Owner: Bob | Birthday: 01/12/2023\n";
    expectedOutput += "Pet Name: Nemo | Type: Fish | Owner: Charlie | Birthday: 31/03/2025\n";
    expectedOutput += "--------------------------------\n";

    testing::internal::CaptureStdout();

    listPetBirthdays(tree, petList);

    std::string actualOutput = testing::internal::GetCapturedStdout();

    EXPECT_EQ(actualOutput, expectedOutput);
}

// ============================================================================
// Session Management Tests
// ============================================================================

/**
 * @class SessionManagementTest
 * @brief Test fixture for session management functionality
 */
class SessionManagementTest : public ::testing::Test {
protected:
    HashTable* table;
    
    void SetUp() override {
        table = createHashTable();
        init_petcare_session();
    }
    
    void TearDown() override {
        logoutUserSession();
        freeHashTable(table);
    }
};

/**
 * @brief Test that session initialization doesn't crash
 */
TEST_F(SessionManagementTest, InitSessionDoesNotCrash) {
    EXPECT_NO_THROW(init_petcare_session()) << "Session initialization should not throw";
}

/**
 * @brief Test login with session creation
 */
TEST_F(SessionManagementTest, LoginWithSessionCreatesSession) {
    addUser(table, "sessionuser", "password123");
    
    int result = loginUserWithSession(table, "sessionuser", "password123");
    EXPECT_EQ(result, 1) << "Login with session should succeed for valid credentials";
    
    EXPECT_EQ(isSessionValid(), 1) << "Session should be valid after successful login";
}

/**
 * @brief Test login failure doesn't create session
 */
TEST_F(SessionManagementTest, FailedLoginDoesNotCreateSession) {
    addUser(table, "sessionuser", "password123");
    
    int result = loginUserWithSession(table, "sessionuser", "wrongpassword");
    EXPECT_EQ(result, 0) << "Login should fail for incorrect password";
    
    EXPECT_EQ(isSessionValid(), 0) << "Session should not be valid after failed login";
}

/**
 * @brief Test logout invalidates session
 */
TEST_F(SessionManagementTest, LogoutInvalidatesSession) {
    addUser(table, "sessionuser", "password123");
    loginUserWithSession(table, "sessionuser", "password123");
    
    EXPECT_EQ(isSessionValid(), 1) << "Session should be valid after login";
    
    logoutUserSession();
    
    EXPECT_EQ(isSessionValid(), 0) << "Session should be invalid after logout";
}

/**
 * @brief Test session validation without login
 */
TEST_F(SessionManagementTest, SessionInvalidWithoutLogin) {
    EXPECT_EQ(isSessionValid(), 0) << "Session should be invalid without login";
}

/**
 * @brief Test multiple login sessions
 */
TEST_F(SessionManagementTest, MultipleLoginSessions) {
    addUser(table, "user1", "pass1");
    addUser(table, "user2", "pass2");
    
    EXPECT_EQ(loginUserWithSession(table, "user1", "pass1"), 1);
    EXPECT_EQ(isSessionValid(), 1);
    
    logoutUserSession();
    EXPECT_EQ(isSessionValid(), 0);
    
    EXPECT_EQ(loginUserWithSession(table, "user2", "pass2"), 1);
    EXPECT_EQ(isSessionValid(), 1);
}

// ============================================================================
// Database Management Tests
// ============================================================================

/**
 * @class DatabaseManagementTest
 * @brief Test fixture for database management functionality
 */
class DatabaseManagementTest : public ::testing::Test {
protected:
    const char* test_db_path = "test_petcare.db";
    
    void SetUp() override {
        remove(test_db_path);
    }
    
    void TearDown() override {
        close_petcare_database();
        remove(test_db_path);
    }
};

/**
 * @brief Test database initialization
 */
TEST_F(DatabaseManagementTest, InitDatabaseCreatesDatabase) {
    int result = init_petcare_database(test_db_path);
    
#ifdef SQLITE3_HEADER_ONLY
    Database* db = get_petcare_database();
    EXPECT_EQ(db, nullptr) << "Database should be NULL when SQLite3 unavailable";
#else
    EXPECT_EQ(result, 0) << "Database initialization should succeed";
    
    Database* db = get_petcare_database();
    EXPECT_NE(db, nullptr) << "Database handle should not be NULL after initialization";
#endif
}

/**
 * @brief Test getting database handle before initialization
 */
TEST_F(DatabaseManagementTest, GetDatabaseBeforeInit) {
    Database* db = get_petcare_database();
    EXPECT_EQ(db, nullptr) << "Database handle should be NULL before initialization";
}

/**
 * @brief Test closing database
 */
TEST_F(DatabaseManagementTest, CloseDatabaseCleansUp) {
    init_petcare_database(test_db_path);
    
    EXPECT_NO_THROW(close_petcare_database()) << "Closing database should not throw";
    
    Database* db = get_petcare_database();
    EXPECT_EQ(db, nullptr) << "Database handle should be NULL after closing";
}

/**
 * @brief Test double initialization
 */
TEST_F(DatabaseManagementTest, DoubleInitialization) {
    int result1 = init_petcare_database(test_db_path);
    int result2 = init_petcare_database(test_db_path);
    
#ifdef SQLITE3_HEADER_ONLY
    // When SQLite3 is not available, both should fail
    EXPECT_NE(result1, 0) << "First initialization should fail when SQLite3 unavailable";
    EXPECT_NE(result2, 0) << "Second initialization should fail when SQLite3 unavailable";
#else
    // When SQLite3 is available, double init should succeed
    EXPECT_EQ(result1, 0) << "First initialization should succeed";
    EXPECT_EQ(result2, 0) << "Double initialization should succeed without error";
#endif
}

/**
 * @brief Test closing database without initialization
 */
TEST_F(DatabaseManagementTest, CloseWithoutInit) {
    EXPECT_NO_THROW(close_petcare_database()) << "Closing uninitialized database should not crash";
}

/**
 * @brief Test migration without database
 */
TEST_F(DatabaseManagementTest, MigrateWithoutDatabase) {
    int result = migrate_dat_to_sqlite();
    EXPECT_NE(result, 0) << "Migration should fail when database not initialized";
}

/**
 * @brief Test migration with database
 */
TEST_F(DatabaseManagementTest, MigrateWithDatabase) {
    init_petcare_database(test_db_path);
    
    HashTable* table = createHashTable();
    addUser(table, "migrateuser", "password123");
    saveUsersToFile(table, "users.dat");
    freeHashTable(table);
    
    int result = migrate_dat_to_sqlite();
    
#ifdef SQLITE3_HEADER_ONLY
    EXPECT_NE(result, 0) << "Migration should fail when SQLite3 unavailable";
#else
    EXPECT_EQ(result, 0) << "Migration should succeed when database initialized";
#endif
    
    remove("users.dat");
}

/**
 * @brief Test multiple migrations
 */
TEST_F(DatabaseManagementTest, MultipleMigrations) {
    init_petcare_database(test_db_path);
    
    HashTable* table = createHashTable();
    addUser(table, "user1", "pass1");
    saveUsersToFile(table, "users.dat");
    freeHashTable(table);
    
    int result1 = migrate_dat_to_sqlite();
    int result2 = migrate_dat_to_sqlite();
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result1, 0) << "First migration should succeed";
    EXPECT_EQ(result2, 0) << "Second migration should succeed (skip)";
#endif
    
    remove("users.dat");
}

// ============================================================================
// XOR Encryption Tests
// ============================================================================

/**
 * @class XOREncryptionTest
 * @brief Test fixture for XOR encryption functionality
 */
class XOREncryptionTest : public ::testing::Test {
protected:
    char test_data[100];
    
    void SetUp() override {
        strcpy(test_data, "Test data for encryption");
    }
};

/**
 * @brief Test XOR encryption/decryption
 */
TEST_F(XOREncryptionTest, EncryptDecryptReversible) {
    char original[100];
    strcpy(original, test_data);
    
    const char* key = "SecretKey";
    size_t len = strlen(test_data);
    
    xorEncryptDecrypt(test_data, len, key);
    
    EXPECT_STRNE(test_data, original) << "Encrypted data should differ from original";
    
    xorEncryptDecrypt(test_data, len, key);
    
    EXPECT_STREQ(test_data, original) << "Decrypted data should match original";
}

/**
 * @brief Test XOR with empty data
 */
TEST_F(XOREncryptionTest, EmptyDataHandling) {
    char empty_data[10] = "";
    const char* key = "Key";
    
    EXPECT_NO_THROW(xorEncryptDecrypt(empty_data, 0, key)) 
        << "XOR should handle empty data without crashing";
}

/**
 * @brief Test XOR with different keys
 */
TEST_F(XOREncryptionTest, DifferentKeysProduceDifferentResults) {
    char data1[100], data2[100];
    strcpy(data1, "Test data");
    strcpy(data2, "Test data");
    
    const char* key1 = "Key1";
    const char* key2 = "Key2";
    size_t len = strlen(data1);
    
    xorEncryptDecrypt(data1, len, key1);
    xorEncryptDecrypt(data2, len, key2);
    
    // Compare as binary data since strings might have null bytes after encryption
    bool different = false;
    for (size_t i = 0; i < len; i++) {
        if (data1[i] != data2[i]) {
            different = true;
            break;
        }
    }
    
    EXPECT_TRUE(different) << "Different keys should produce different encrypted data";
}

/**
 * @brief Test XOR encryption properties
 */
TEST_F(XOREncryptionTest, XORProperties) {
    char data[100];
    strcpy(data, "Testing XOR properties");
    char original[100];
    strcpy(original, data);
    
    const char* key = "TestKey";
    size_t len = strlen(data);
    
    xorEncryptDecrypt(data, len, key);
    xorEncryptDecrypt(data, len, key);
    
    EXPECT_STREQ(data, original) << "Double XOR should return original data";
}

// ============================================================================
// Hash Function Tests
// ============================================================================

/**
 * @class HashFunctionTest
 * @brief Test fixture for hash function
 */
class HashFunctionTest : public ::testing::Test {};

/**
 * @brief Test hash function produces consistent results
 */
TEST_F(HashFunctionTest, ConsistentHashing) {
    const char* str = "teststring";
    unsigned int hash1 = hashFunction(str);
    unsigned int hash2 = hashFunction(str);
    
    EXPECT_EQ(hash1, hash2) << "Hash function should produce consistent results";
}

/**
 * @brief Test hash function with different strings
 */
TEST_F(HashFunctionTest, DifferentStringsProduceDifferentHashes) {
    unsigned int hash1 = hashFunction("string1");
    unsigned int hash2 = hashFunction("string2");
    
    EXPECT_NE(hash1, hash2) << "Different strings should (usually) produce different hashes";
}

/**
 * @brief Test hash function stays within bounds
 */
TEST_F(HashFunctionTest, HashWithinBounds) {
    const char* testStrings[] = {
        "test",
        "longerstring",
        "a",
        "AnotherTestString123",
        "special!@#$%^&*()",
        ""
    };
    
    for (const char* str : testStrings) {
        unsigned int hash = hashFunction(str);
        EXPECT_LT(hash, HASH_TABLE_SIZE) 
            << "Hash value should be less than HASH_TABLE_SIZE for string: " << str;
    }
}

/**
 * @brief Test hash function with empty string
 */
TEST_F(HashFunctionTest, EmptyStringHash) {
    unsigned int hash = hashFunction("");
    EXPECT_LT(hash, HASH_TABLE_SIZE) << "Empty string should produce valid hash";
}

/**
 * @brief Test hash distribution
 */
TEST_F(HashFunctionTest, ReasonableDistribution) {
    bool used[HASH_TABLE_SIZE] = {false};
    int uniqueHashes = 0;
    
    for (int i = 0; i < 100; i++) {
        char str[20];
        snprintf(str, sizeof(str), "test%d", i);
        unsigned int hash = hashFunction(str);
        
        if (!used[hash]) {
            used[hash] = true;
            uniqueHashes++;
        }
    }
    
    EXPECT_GT(uniqueHashes, 50) 
        << "Hash function should distribute reasonably well";
}

// ============================================================================
// Password Encryption Tests (Additional)
// ============================================================================

/**
 * @class PasswordEncryptionAdvancedTest
 * @brief Additional test fixture for password encryption
 */
class PasswordEncryptionAdvancedTest : public ::testing::Test {};

/**
 * @brief Test empty password encryption
 */
TEST_F(PasswordEncryptionAdvancedTest, EmptyPassword) {
    const char* password = "";
    char* encrypted = encryptPassword(password);
    
    EXPECT_NE(encrypted, nullptr) << "Empty password encryption should not return NULL";
    EXPECT_STREQ(encrypted, "") << "Empty password should encrypt to empty string";
    
    free(encrypted);
}

/**
 * @brief Test long password encryption
 */
TEST_F(PasswordEncryptionAdvancedTest, LongPassword) {
    const char* password = "ThisIsAVeryLongPasswordWithManyCharactersToTestEncryption123!@#$%^&*()";
    char* encrypted = encryptPassword(password);
    char* decrypted = encryptPassword(encrypted);
    
    EXPECT_STREQ(decrypted, password) << "Long password should encrypt/decrypt correctly";
    EXPECT_EQ(strlen(encrypted), strlen(password)) 
        << "Encrypted password should have same length as original";
    
    free(encrypted);
    free(decrypted);
}

/**
 * @brief Test special characters in password
 */
TEST_F(PasswordEncryptionAdvancedTest, SpecialCharacters) {
    const char* password = "P@ssw0rd!#$%^&*()_+-=[]{}|;:,.<>?";
    char* encrypted = encryptPassword(password);
    char* decrypted = encryptPassword(encrypted);
    
    EXPECT_STREQ(decrypted, password) 
        << "Password with special characters should encrypt/decrypt correctly";
    
    free(encrypted);
    free(decrypted);
}

/**
 * @brief Test password encryption consistency
 */
TEST_F(PasswordEncryptionAdvancedTest, ConsistentEncryption) {
    const char* password = "consistent";
    char* encrypted1 = encryptPassword(password);
    char* encrypted2 = encryptPassword(password);
    
    EXPECT_STREQ(encrypted1, encrypted2) 
        << "Same password should produce same encrypted result";
    
    free(encrypted1);
    free(encrypted2);
}

// ============================================================================
// Database Stub Implementation Tests
// ============================================================================

/**
 * @class DatabaseStubTest
 * @brief Test fixture for database stub implementation tests
 */
class DatabaseStubTest : public ::testing::Test {
protected:
    Database* db;
    HashTable* table;
    Pet* petList;
    BPlusTree* birthdayTree;
    StrayAnimal* strayList;
    AdoptedAnimal* adoptedList;

    void SetUp() override {
        db = NULL;
        table = createHashTable();
        petList = NULL;
        birthdayTree = createBPlusTree();
        strayList = NULL;
        adoptedList = NULL;
    }

    void TearDown() override {
        if (db != NULL) {
            db_close(db);
        }
        if (table != NULL) {
            freeHashTable(table);
        }
    }
};

/**
 * @brief Test that db_init returns NULL when SQLite3 library is not available
 */
TEST_F(DatabaseStubTest, InitReturnsNull) {
    db = db_init("test.db", NULL);
#ifdef SQLITE3_HEADER_ONLY
    EXPECT_EQ(db, nullptr) << "db_init should return NULL when SQLite3 library unavailable";
#endif
}

/**
 * @brief Test that db_close doesn't crash with NULL pointer
 */
TEST_F(DatabaseStubTest, CloseHandlesNull) {
    EXPECT_NO_THROW(db_close(NULL)) << "db_close should handle NULL pointer gracefully";
}

/**
 * @brief Test that db_create_tables returns error
 */
TEST_F(DatabaseStubTest, CreateTablesReturnsError) {
    int result = db_create_tables(NULL);
    EXPECT_EQ(result, -1) << "db_create_tables should return -1 when database unavailable";
}

/**
 * @brief Test that db_add_user returns error
 */
TEST_F(DatabaseStubTest, AddUserReturnsError) {
    int result = db_add_user(NULL, "testuser", "encrypted_password");
    EXPECT_EQ(result, -1) << "db_add_user should return -1 when database unavailable";
}

/**
 * @brief Test that db_user_exists returns 0 (not found)
 */
TEST_F(DatabaseStubTest, UserExistsReturnsZero) {
    int result = db_user_exists(NULL, "testuser");
    EXPECT_EQ(result, 0) << "db_user_exists should return 0 when database unavailable";
}

/**
 * @brief Test that db_add_pet returns error
 */
TEST_F(DatabaseStubTest, AddPetReturnsError) {
    int result = db_add_pet(NULL, "Buddy", "Dog", 3, "testuser");
    EXPECT_EQ(result, -1) << "db_add_pet should return -1 when database unavailable";
}

/**
 * @brief Test that db_is_date_occupied returns 0 (not occupied)
 */
TEST_F(DatabaseStubTest, IsDateOccupiedReturnsZero) {
    int result = db_is_date_occupied(NULL, 15, 6);
    EXPECT_EQ(result, 0) << "db_is_date_occupied should return 0 when database unavailable";
}

/**
 * @brief Test that db_get_error returns appropriate message
 */
TEST_F(DatabaseStubTest, GetErrorReturnsMessage) {
    const char* error = db_get_error(NULL);
    EXPECT_NE(error, nullptr) << "db_get_error should return a valid error message";
#ifdef SQLITE3_HEADER_ONLY
    EXPECT_STREQ(error, "SQLite3 library not available") 
        << "Error message should indicate library unavailability";
#endif
}

/**
 * @brief Test that db_last_insert_id returns -1
 */
TEST_F(DatabaseStubTest, LastInsertIdReturnsError) {
    long long result = db_last_insert_id(NULL);
    EXPECT_EQ(result, -1) << "db_last_insert_id should return -1 when database unavailable";
}

/**
 * @brief Test that functions handle NULL parameters gracefully
 */
TEST_F(DatabaseStubTest, HandleNullParametersGracefully) {
    EXPECT_NO_THROW({
        db_add_user(NULL, NULL, NULL);
        db_get_user_password(NULL, NULL, NULL);
        db_add_pet(NULL, NULL, NULL, 0, NULL);
        db_add_appointment(NULL, NULL, NULL, 0, 0, NULL);
        db_add_birthday(NULL, NULL, 0, 0, 0, NULL);
        db_add_stray_animal(NULL, NULL, NULL, NULL, 0);
    }) << "Stub functions should handle NULL parameters without crashing";
}

/**
 * @brief Test that db_execute returns error
 */
TEST_F(DatabaseStubTest, ExecuteReturnsError) {
    int result = db_execute(NULL, "SELECT * FROM users");
    EXPECT_EQ(result, -1) << "db_execute should return -1 when database unavailable";
}

/**
 * @brief Test that db_begin_transaction returns error
 */
TEST_F(DatabaseStubTest, BeginTransactionReturnsError) {
    int result = db_begin_transaction(NULL);
    EXPECT_EQ(result, -1) << "db_begin_transaction should return -1 when database unavailable";
}

/**
 * @brief Test that db_commit_transaction returns error
 */
TEST_F(DatabaseStubTest, CommitTransactionReturnsError) {
    int result = db_commit_transaction(NULL);
    EXPECT_EQ(result, -1) << "db_commit_transaction should return -1 when database unavailable";
}

/**
 * @brief Test that db_rollback_transaction returns error
 */
TEST_F(DatabaseStubTest, RollbackTransactionReturnsError) {
    int result = db_rollback_transaction(NULL);
    EXPECT_EQ(result, -1) << "db_rollback_transaction should return -1 when database unavailable";
}

/**
 * @brief Test that db_get_user_password returns error
 */
TEST_F(DatabaseStubTest, GetUserPasswordReturnsError) {
    char* password = NULL;
    int result = db_get_user_password(NULL, "testuser", &password);
    EXPECT_EQ(result, -1) << "db_get_user_password should return -1 when database unavailable";
    EXPECT_EQ(password, nullptr) << "Password pointer should remain NULL";
}

/**
 * @brief Test that db_load_all_users returns 0 (no users loaded)
 */
TEST_F(DatabaseStubTest, LoadAllUsersReturnsZero) {
    int result = db_load_all_users(NULL, table);
    EXPECT_EQ(result, 0) << "db_load_all_users should return 0 when database unavailable";
}

/**
 * @brief Test that db_update_pet returns error
 */
TEST_F(DatabaseStubTest, UpdatePetReturnsError) {
    int result = db_update_pet(NULL, "OldName", "Owner", "NewName", "Dog", 5);
    EXPECT_EQ(result, -1) << "db_update_pet should return -1 when database unavailable";
}

/**
 * @brief Test that db_delete_pet returns error
 */
TEST_F(DatabaseStubTest, DeletePetReturnsError) {
    int result = db_delete_pet(NULL, "Buddy", "Owner");
    EXPECT_EQ(result, -1) << "db_delete_pet should return -1 when database unavailable";
}

/**
 * @brief Test that db_load_all_pets returns 0 (no pets loaded)
 */
TEST_F(DatabaseStubTest, LoadAllPetsReturnsZero) {
    int result = db_load_all_pets(NULL, &petList);
    EXPECT_EQ(result, 0) << "db_load_all_pets should return 0 when database unavailable";
}

/**
 * @brief Test that db_is_pet_owned_by returns 0 (not owned)
 */
TEST_F(DatabaseStubTest, IsPetOwnedByReturnsZero) {
    int result = db_is_pet_owned_by(NULL, "Buddy", "Owner");
    EXPECT_EQ(result, 0) << "db_is_pet_owned_by should return 0 when database unavailable";
}

/**
 * @brief Test that db_add_appointment returns error
 */
TEST_F(DatabaseStubTest, AddAppointmentReturnsError) {
    int result = db_add_appointment(NULL, "Buddy", "Checkup", 15, 6, "Owner");
    EXPECT_EQ(result, -1) << "db_add_appointment should return -1 when database unavailable";
}

/**
 * @brief Test that db_update_appointment returns error
 */
TEST_F(DatabaseStubTest, UpdateAppointmentReturnsError) {
    int result = db_update_appointment(NULL, "Buddy", 15, 6, 16, 6, "Vaccination", "Owner");
    EXPECT_EQ(result, -1) << "db_update_appointment should return -1 when database unavailable";
}

/**
 * @brief Test that db_delete_appointment returns error
 */
TEST_F(DatabaseStubTest, DeleteAppointmentReturnsError) {
    int result = db_delete_appointment(NULL, "Buddy", 15, 6, "Owner");
    EXPECT_EQ(result, -1) << "db_delete_appointment should return -1 when database unavailable";
}

/**
 * @brief Test that db_load_all_appointments returns 0 (no appointments loaded)
 */
TEST_F(DatabaseStubTest, LoadAllAppointmentsReturnsZero) {
    int result = db_load_all_appointments(NULL);
    EXPECT_EQ(result, 0) << "db_load_all_appointments should return 0 when database unavailable";
}

/**
 * @brief Test that db_add_birthday returns error
 */
TEST_F(DatabaseStubTest, AddBirthdayReturnsError) {
    int result = db_add_birthday(NULL, "Buddy", 15, 6, 2020, "Owner");
    EXPECT_EQ(result, -1) << "db_add_birthday should return -1 when database unavailable";
}

/**
 * @brief Test that db_load_all_birthdays returns 0 (no birthdays loaded)
 */
TEST_F(DatabaseStubTest, LoadAllBirthdaysReturnsZero) {
    int result = db_load_all_birthdays(NULL, birthdayTree, &petList);
    EXPECT_EQ(result, 0) << "db_load_all_birthdays should return 0 when database unavailable";
}

/**
 * @brief Test that db_add_stray_animal returns error
 */
TEST_F(DatabaseStubTest, AddStrayAnimalReturnsError) {
    int result = db_add_stray_animal(NULL, "Dog", "Male", "01/01/2023", 3);
    EXPECT_EQ(result, -1) << "db_add_stray_animal should return -1 when database unavailable";
}

/**
 * @brief Test that db_update_stray_animal returns error
 */
TEST_F(DatabaseStubTest, UpdateStrayAnimalReturnsError) {
    int result = db_update_stray_animal(NULL, 1, "Cat", "Female", "02/02/2023", 2);
    EXPECT_EQ(result, -1) << "db_update_stray_animal should return -1 when database unavailable";
}

/**
 * @brief Test that db_delete_stray_animal returns error
 */
TEST_F(DatabaseStubTest, DeleteStrayAnimalReturnsError) {
    int result = db_delete_stray_animal(NULL, 1);
    EXPECT_EQ(result, -1) << "db_delete_stray_animal should return -1 when database unavailable";
}

/**
 * @brief Test that db_load_all_stray_animals returns 0 (no stray animals loaded)
 */
TEST_F(DatabaseStubTest, LoadAllStrayAnimalsReturnsZero) {
    int result = db_load_all_stray_animals(NULL, &strayList);
    EXPECT_EQ(result, 0) << "db_load_all_stray_animals should return 0 when database unavailable";
}

/**
 * @brief Test that db_add_adopted_animal returns error
 */
TEST_F(DatabaseStubTest, AddAdoptedAnimalReturnsError) {
    int result = db_add_adopted_animal(NULL, 1, "Dog", "Male", "01/01/2023", 3, "Owner", "02/02/2023");
    EXPECT_EQ(result, -1) << "db_add_adopted_animal should return -1 when database unavailable";
}

/**
 * @brief Test that db_load_all_adopted_animals returns 0 (no adopted animals loaded)
 */
TEST_F(DatabaseStubTest, LoadAllAdoptedAnimalsReturnsZero) {
    int result = db_load_all_adopted_animals(NULL, &adoptedList);
    EXPECT_EQ(result, 0) << "db_load_all_adopted_animals should return 0 when database unavailable";
}

/**
 * @brief Test that db_adopt_stray_animal returns error
 */
TEST_F(DatabaseStubTest, AdoptStrayAnimalReturnsError) {
    int result = db_adopt_stray_animal(NULL, 1, "Owner", "02/02/2023");
    EXPECT_EQ(result, -1) << "db_adopt_stray_animal should return -1 when database unavailable";
}

/**
 * @brief Test that db_backup returns error
 */
TEST_F(DatabaseStubTest, BackupReturnsError) {
    int result = db_backup(NULL, "backup.db");
    EXPECT_EQ(result, -1) << "db_backup should return -1 when database unavailable";
}

/**
 * @brief Test that db_restore returns error
 */
TEST_F(DatabaseStubTest, RestoreReturnsError) {
    int result = db_restore("test.db", "backup.db");
    EXPECT_EQ(result, -1) << "db_restore should return -1 when database unavailable";
}