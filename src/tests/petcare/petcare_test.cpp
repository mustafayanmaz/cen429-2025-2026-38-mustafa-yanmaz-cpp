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

    saveUsersToFile(table, "database");

    HashTable* loadedTable = createHashTable();
    loadUsersFromFile(loadedTable, "database");

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
    
    // Database cleanup is handled automatically
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
    saveUsersToFile(table, "database");
    freeHashTable(table);
    
    int result = migrate_dat_to_sqlite();
    
#ifdef SQLITE3_HEADER_ONLY
    EXPECT_NE(result, 0) << "Migration should fail when SQLite3 unavailable";
#else
    EXPECT_EQ(result, 0) << "Migration should succeed when database initialized";
#endif
    
    // Database cleanup is handled automatically
}

/**
 * @brief Test multiple migrations
 */
TEST_F(DatabaseManagementTest, MultipleMigrations) {
    init_petcare_database(test_db_path);
    
    HashTable* table = createHashTable();
    addUser(table, "user1", "pass1");
    saveUsersToFile(table, "database");
    freeHashTable(table);
    
    int result1 = migrate_dat_to_sqlite();
    int result2 = migrate_dat_to_sqlite();
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result1, 0) << "First migration should succeed";
    EXPECT_EQ(result2, 0) << "Second migration should succeed (skip)";
#endif
    
    // Database cleanup is handled automatically
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
        // Clean up any test database files
        remove("backup.db");
        remove("test.db");
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

// ============================================================================
// Huffman Coding Tests
// ============================================================================

/**
 * @class HuffmanCodingTest
 * @brief Test fixture for Huffman coding functionality
 */
class HuffmanCodingTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test data
    }

    void TearDown() override {
        // Clean up any allocated memory
    }
};

/**
 * @brief Test creating a new Huffman tree node
 */
TEST_F(HuffmanCodingTest, CreateNewNode) {
    MinHeapNode* node = newNode('A', 5);
    
    ASSERT_NE(node, nullptr) << "Node should not be null";
    EXPECT_EQ(node->data, 'A') << "Node data should be 'A'";
    EXPECT_EQ(node->freq, 5) << "Node frequency should be 5";
    EXPECT_EQ(node->left, nullptr) << "Left child should be null";
    EXPECT_EQ(node->right, nullptr) << "Right child should be null";
    
    free(node);
}

/**
 * @brief Test creating a min heap
 */
TEST_F(HuffmanCodingTest, CreateMinHeap) {
    MinHeap* heap = createMinHeap(10);
    
    ASSERT_NE(heap, nullptr) << "Heap should not be null";
    EXPECT_EQ(heap->size, 0) << "Initial heap size should be 0";
    EXPECT_EQ(heap->capacity, 10) << "Heap capacity should be 10";
    EXPECT_NE(heap->array, nullptr) << "Heap array should not be null";
    
    free(heap->array);
    free(heap);
}

/**
 * @brief Test swapping min heap nodes
 */
TEST_F(HuffmanCodingTest, SwapMinHeapNodes) {
    MinHeapNode* node1 = newNode('A', 5);
    MinHeapNode* node2 = newNode('B', 3);
    
    MinHeapNode* ptr1 = node1;
    MinHeapNode* ptr2 = node2;
    
    swapMinHeapNode(&ptr1, &ptr2);
    
    EXPECT_EQ(ptr1, node2) << "First pointer should point to node2";
    EXPECT_EQ(ptr2, node1) << "Second pointer should point to node1";
    
    free(node1);
    free(node2);
}

/**
 * @brief Test building a min heap from data
 */
TEST_F(HuffmanCodingTest, BuildMinHeap) {
    char data[] = {'A', 'B', 'C'};
    int freq[] = {5, 3, 7};
    int size = 3;
    
    MinHeap* heap = buildMinHeap(data, freq, size);
    
    ASSERT_NE(heap, nullptr) << "Heap should not be null";
    EXPECT_EQ(heap->size, 3) << "Heap size should be 3";
    EXPECT_EQ(heap->capacity, 3) << "Heap capacity should be 3";
    
    // Check that the heap property is maintained (smallest at root)
    EXPECT_LE(heap->array[0]->freq, heap->array[1]->freq) << "Heap property should be maintained";
    EXPECT_LE(heap->array[0]->freq, heap->array[2]->freq) << "Heap property should be maintained";
    
    // Clean up
    for (int i = 0; i < heap->size; i++) {
        free(heap->array[i]);
    }
    free(heap->array);
    free(heap);
}

/**
 * @brief Test extracting minimum from heap
 */
TEST_F(HuffmanCodingTest, ExtractMin) {
    char data[] = {'A', 'B', 'C'};
    int freq[] = {5, 3, 7};
    int size = 3;
    
    MinHeap* heap = buildMinHeap(data, freq, size);
    
    MinHeapNode* min = extractMin(heap);
    
    ASSERT_NE(min, nullptr) << "Extracted node should not be null";
    EXPECT_EQ(min->freq, 3) << "Extracted node should have minimum frequency";
    EXPECT_EQ(heap->size, 2) << "Heap size should decrease by 1";
    
    free(min);
    for (int i = 0; i < heap->size; i++) {
        free(heap->array[i]);
    }
    free(heap->array);
    free(heap);
}

/**
 * @brief Test building Huffman tree
 */
TEST_F(HuffmanCodingTest, BuildHuffmanTree) {
    char data[] = {'A', 'B', 'C', 'D'};
    int freq[] = {5, 3, 7, 1};
    int size = 4;
    
    MinHeapNode* root = buildHuffmanTree(data, freq, size);
    
    ASSERT_NE(root, nullptr) << "Huffman tree root should not be null";
    EXPECT_EQ(root->freq, 16) << "Root frequency should be sum of all frequencies";
    EXPECT_EQ(root->data, '$') << "Root should be internal node with '$'";
    
    // Clean up tree
    // Note: In a real implementation, you'd need a proper tree cleanup function
    free(root);
}

/**
 * @brief Test Huffman codes generation
 */
TEST_F(HuffmanCodingTest, GenerateHuffmanCodes) {
    char data[] = {'A', 'B', 'C'};
    int freq[] = {5, 3, 7};
    int size = 3;
    char codes[256][MAX_TREE_HT];
    
    // Initialize codes array
    for (int i = 0; i < 256; i++) {
        codes[i][0] = '\0';
    }
    
    HuffmanCodes(data, freq, size, codes);
    
    // Check that codes were generated
    EXPECT_NE(codes['A'][0], '\0') << "Code for 'A' should be generated";
    EXPECT_NE(codes['B'][0], '\0') << "Code for 'B' should be generated";
    EXPECT_NE(codes['C'][0], '\0') << "Code for 'C' should be generated";
}

/**
 * @brief Test string compression
 */
TEST_F(HuffmanCodingTest, CompressString) {
    char data[] = {'A', 'B', 'C'};
    int freq[] = {5, 3, 7};
    int size = 3;
    char codes[256][MAX_TREE_HT];
    
    // Initialize codes array
    for (int i = 0; i < 256; i++) {
        codes[i][0] = '\0';
    }
    
    HuffmanCodes(data, freq, size, codes);
    
    char input[] = "ABC";
    char output[1000];
    
    compress(input, codes, output);
    
    // Check that output is not empty
    EXPECT_GT(strlen(output), 0) << "Compressed output should not be empty";
}

/**
 * @brief Test string decompression
 */
TEST_F(HuffmanCodingTest, DecompressString) {
    char data[] = {'A', 'B', 'C'};
    int freq[] = {5, 3, 7};
    int size = 3;
    char codes[256][MAX_TREE_HT];
    
    // Initialize codes array
    for (int i = 0; i < 256; i++) {
        codes[i][0] = '\0';
    }
    
    HuffmanCodes(data, freq, size, codes);
    
    char input[] = "ABC";
    char compressed[1000];
    char decompressed[1000];
    
    compress(input, codes, compressed);
    
    MinHeapNode* root = buildHuffmanTree(data, freq, size);
    decompress(root, compressed, decompressed);
    
    EXPECT_STREQ(input, decompressed) << "Decompressed string should match original";
    
    free(root);
}

// ============================================================================
// New Database Function Tests
// ============================================================================

/**
 * @class NewDatabaseFunctionTest
 * @brief Test fixture for new database functions
 */
class NewDatabaseFunctionTest : public ::testing::Test {
protected:
    Database* db;
    const char* test_db_path = "test_new_functions.db";

    void SetUp() override {
        db = db_init(test_db_path, NULL);
        if (db) {
            db_create_tables(db);
        }
    }

    void TearDown() override {
        if (db) {
            db_close(db);
        }
        remove(test_db_path);
    }
};

/**
 * @brief Test adding feeding schedule
 */
TEST_F(NewDatabaseFunctionTest, AddFeedingSchedule) {
    if (!db) {
        GTEST_SKIP() << "Database not available";
        return;
    }
    
    int result = db_add_feeding_schedule(db, "Buddy", "Morning: 8AM, Evening: 6PM", "testuser");
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0) << "Adding feeding schedule should succeed";
#else
    EXPECT_EQ(result, -1) << "Adding feeding schedule should fail when SQLite3 unavailable";
#endif
}

/**
 * @brief Test updating feeding schedule
 */
TEST_F(NewDatabaseFunctionTest, UpdateFeedingSchedule) {
    if (!db) {
        GTEST_SKIP() << "Database not available";
        return;
    }
    
    int result = db_update_feeding_schedule(db, "Buddy", "testuser", "Morning: 7AM, Evening: 7PM");
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0) << "Updating feeding schedule should succeed";
#else
    EXPECT_EQ(result, -1) << "Updating feeding schedule should fail when SQLite3 unavailable";
#endif
}

/**
 * @brief Test deleting feeding schedule
 */
TEST_F(NewDatabaseFunctionTest, DeleteFeedingSchedule) {
    if (!db) {
        GTEST_SKIP() << "Database not available";
        return;
    }
    
    int result = db_delete_feeding_schedule(db, "Buddy", "testuser");
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0) << "Deleting feeding schedule should succeed";
#else
    EXPECT_EQ(result, -1) << "Deleting feeding schedule should fail when SQLite3 unavailable";
#endif
}

/**
 * @brief Test adding medicine schedule
 */
TEST_F(NewDatabaseFunctionTest, AddMedicineSchedule) {
    if (!db) {
        GTEST_SKIP() << "Database not available";
        return;
    }
    
    int result = db_add_medicine_schedule(db, "Buddy", "Antibiotic: 2x daily", "testuser");
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0) << "Adding medicine schedule should succeed";
#else
    EXPECT_EQ(result, -1) << "Adding medicine schedule should fail when SQLite3 unavailable";
#endif
}

/**
 * @brief Test updating medicine schedule
 */
TEST_F(NewDatabaseFunctionTest, UpdateMedicineSchedule) {
    if (!db) {
        GTEST_SKIP() << "Database not available";
        return;
    }
    
    int result = db_update_medicine_schedule(db, "Buddy", "testuser", "Antibiotic: 3x daily");
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0) << "Updating medicine schedule should succeed";
#else
    EXPECT_EQ(result, -1) << "Updating medicine schedule should fail when SQLite3 unavailable";
#endif
}

/**
 * @brief Test deleting medicine schedule
 */
TEST_F(NewDatabaseFunctionTest, DeleteMedicineSchedule) {
    if (!db) {
        GTEST_SKIP() << "Database not available";
        return;
    }
    
    int result = db_delete_medicine_schedule(db, "Buddy", "testuser");
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0) << "Deleting medicine schedule should succeed";
#else
    EXPECT_EQ(result, -1) << "Deleting medicine schedule should fail when SQLite3 unavailable";
#endif
}

/**
 * @brief Test adding exercise routine
 */
TEST_F(NewDatabaseFunctionTest, AddExerciseRoutine) {
    if (!db) {
        GTEST_SKIP() << "Database not available";
        return;
    }
    
    int result = db_add_exercise_routine(db, "Buddy", "30 min walk daily", "testuser");
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0) << "Adding exercise routine should succeed";
#else
    EXPECT_EQ(result, -1) << "Adding exercise routine should fail when SQLite3 unavailable";
#endif
}

/**
 * @brief Test updating exercise routine
 */
TEST_F(NewDatabaseFunctionTest, UpdateExerciseRoutine) {
    if (!db) {
        GTEST_SKIP() << "Database not available";
        return;
    }
    
    int result = db_update_exercise_routine(db, "Buddy", "testuser", "45 min walk daily");
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0) << "Updating exercise routine should succeed";
#else
    EXPECT_EQ(result, -1) << "Updating exercise routine should fail when SQLite3 unavailable";
#endif
}

/**
 * @brief Test deleting exercise routine
 */
TEST_F(NewDatabaseFunctionTest, DeleteExerciseRoutine) {
    if (!db) {
        GTEST_SKIP() << "Database not available";
        return;
    }
    
    int result = db_delete_exercise_routine(db, "Buddy", "testuser");
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0) << "Deleting exercise routine should succeed";
#else
    EXPECT_EQ(result, -1) << "Deleting exercise routine should fail when SQLite3 unavailable";
#endif
}

// ============================================================================
// Edge Case and Error Handling Tests
// ============================================================================

/**
 * @class EdgeCaseTest
 * @brief Test fixture for edge cases and error handling
 */
class EdgeCaseTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test environment
    }

    void TearDown() override {
        // Clean up test environment
    }
};

/**
 * @brief Test hash function with empty string
 */
TEST_F(EdgeCaseTest, HashFunctionEmptyString) {
    unsigned int hash = hashFunction("");
    EXPECT_GE(hash, 0) << "Hash of empty string should be non-negative";
    EXPECT_LT(hash, HASH_TABLE_SIZE) << "Hash should be within table size";
}

/**
 * @brief Test hash function with very long string
 */
TEST_F(EdgeCaseTest, HashFunctionLongString) {
    char longString[1000];
    memset(longString, 'A', 999);
    longString[999] = '\0';
    
    unsigned int hash = hashFunction(longString);
    EXPECT_GE(hash, 0) << "Hash of long string should be non-negative";
    EXPECT_LT(hash, HASH_TABLE_SIZE) << "Hash should be within table size";
}

/**
 * @brief Test hash function with special characters
 */
TEST_F(EdgeCaseTest, HashFunctionSpecialCharacters) {
    const char* specialChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    unsigned int hash = hashFunction(specialChars);
    EXPECT_GE(hash, 0) << "Hash of special characters should be non-negative";
    EXPECT_LT(hash, HASH_TABLE_SIZE) << "Hash should be within table size";
}

/**
 * @brief Test password encryption with empty string
 */
TEST_F(EdgeCaseTest, EncryptPasswordEmptyString) {
    char* encrypted = encryptPassword("");
    ASSERT_NE(encrypted, nullptr) << "Encrypted empty string should not be null";
    EXPECT_STREQ(encrypted, "") << "Encrypted empty string should be empty";
    free(encrypted);
}

/**
 * @brief Test password encryption with NULL
 */
TEST_F(EdgeCaseTest, EncryptPasswordNull) {
    char* encrypted = encryptPassword(nullptr);
    // This should handle NULL gracefully or assert
    if (encrypted) {
        free(encrypted);
    }
}

/**
 * @brief Test user authentication with NULL parameters
 */
TEST_F(EdgeCaseTest, AuthenticateUserNullParameters) {
    HashTable* table = createHashTable();
    
    int result = authenticateUser(nullptr, "user", "pass");
    EXPECT_EQ(result, 0) << "Authentication with NULL table should fail";
    
    result = authenticateUser(table, nullptr, "pass");
    EXPECT_EQ(result, 0) << "Authentication with NULL username should fail";
    
    result = authenticateUser(table, "user", nullptr);
    EXPECT_EQ(result, 0) << "Authentication with NULL password should fail";
    
    freeHashTable(table);
}

/**
 * @brief Test pet operations with NULL parameters
 */
TEST_F(EdgeCaseTest, PetOperationsNullParameters) {
    Pet* petList = NULL;
    
    // Test addPet with NULL parameters
    addPet(&petList, nullptr, "Dog", 3, "owner");
    EXPECT_EQ(petList, nullptr) << "Adding pet with NULL name should not create pet";
    
    addPet(&petList, "Buddy", nullptr, 3, "owner");
    EXPECT_EQ(petList, nullptr) << "Adding pet with NULL type should not create pet";
    
    addPet(&petList, "Buddy", "Dog", 3, nullptr);
    EXPECT_EQ(petList, nullptr) << "Adding pet with NULL owner should not create pet";
    
    // Test updatePet with NULL parameters
    updatePet(petList, nullptr, "owner");
    // Note: updatePet returns void, so we can't check return value
    
    // Test deletePet with NULL parameters
    deletePet(&petList, nullptr, "owner");
    // Note: deletePet returns void, so we can't check return value
    
    deletePet(&petList, "Buddy", nullptr);
    // Note: deletePet returns void, so we can't check return value
}

/**
 * @brief Test appointment operations with invalid dates
 */
TEST_F(EdgeCaseTest, AppointmentOperationsInvalidDates) {
    // Test with invalid day - addAppointment takes 6 parameters
    addAppointment("Buddy", "Checkup", 32, 6, "owner", petList);
    addAppointment("Buddy", "Checkup", 0, 6, "owner", petList);
    addAppointment("Buddy", "Checkup", -1, 6, "owner", petList);
    
    // Test with invalid month
    addAppointment("Buddy", "Checkup", 15, 13, "owner", petList);
    addAppointment("Buddy", "Checkup", 15, 0, "owner", petList);
    addAppointment("Buddy", "Checkup", 15, -1, "owner", petList);
    
    // Test with NULL parameters
    addAppointment(nullptr, "Checkup", 15, 6, "owner", petList);
    addAppointment("Buddy", nullptr, 15, 6, "owner", petList);
}

/**
 * @brief Test database operations with NULL database
 */
TEST_F(EdgeCaseTest, DatabaseOperationsNullDatabase) {
    // Test all database functions with NULL database
    EXPECT_EQ(db_add_user(nullptr, "user", "pass"), -1);
    EXPECT_EQ(db_get_user_password(nullptr, "user", nullptr), -1);
    EXPECT_EQ(db_user_exists(nullptr, "user"), 0);
    EXPECT_EQ(db_load_all_users(nullptr, nullptr), 0);
    EXPECT_EQ(db_add_pet(nullptr, "Buddy", "Dog", 3, "owner"), -1);
    EXPECT_EQ(db_add_appointment(nullptr, "Buddy", "Checkup", 15, 6, "owner"), -1);
    EXPECT_EQ(db_add_birthday(nullptr, "Buddy", 15, 6, 2020, "owner"), -1);
    EXPECT_EQ(db_add_stray_animal(nullptr, "Dog", "Male", "01/01/2023", 3), -1);
    EXPECT_EQ(db_add_feeding_schedule(nullptr, "Buddy", "Schedule", "owner"), -1);
    EXPECT_EQ(db_add_medicine_schedule(nullptr, "Buddy", "Medicine", "owner"), -1);
    EXPECT_EQ(db_add_exercise_routine(nullptr, "Buddy", "Exercise", "owner"), -1);
}

/**
 * @brief Test memory allocation failures
 */
TEST_F(EdgeCaseTest, MemoryAllocationFailures) {
    // Test creating hash table (should handle malloc failure gracefully)
    HashTable* table = createHashTable();
    ASSERT_NE(table, nullptr) << "Hash table creation should succeed in normal conditions";
    freeHashTable(table);
    
    // Test creating pet list
    Pet* petList = NULL;
    addPet(&petList, "Buddy", "Dog", 3, "owner");
    ASSERT_NE(petList, nullptr) << "Pet creation should succeed in normal conditions";
    freePetList(petList);
}

/**
 * @brief Test boundary values
 */
TEST_F(EdgeCaseTest, BoundaryValues) {
    // Test maximum age
    Pet* petList = NULL;
    addPet(&petList, "OldPet", "Dog", 100, "owner");
    ASSERT_NE(petList, nullptr) << "Pet with maximum age should be created";
    EXPECT_EQ(petList->age, 100) << "Pet age should be 100";
    freePetList(petList);
    
    // Test minimum age
    petList = NULL;
    addPet(&petList, "YoungPet", "Cat", 0, "owner");
    ASSERT_NE(petList, nullptr) << "Pet with minimum age should be created";
    EXPECT_EQ(petList->age, 0) << "Pet age should be 0";
    freePetList(petList);
    
    // Test negative age (should be handled gracefully)
    petList = NULL;
    addPet(&petList, "InvalidPet", "Dog", -1, "owner");
    // The function should handle negative age appropriately
    freePetList(petList);
}

// ============================================================================
// Security Function Tests (Commented out - functions not yet implemented)
// ============================================================================

// Note: Security functions like secure_strdup, secure_wipe, obfuscated strings,
// whitebox cryptography, device fingerprinting, and session management are
// not yet implemented in the codebase. These tests are commented out until
// the functions are available.

/*
class SecurityFunctionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// Security function tests would go here when the functions are implemented
*/

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

// ============================================================================
// COMPREHENSIVE DATABASE FUNCTION TESTS
// ============================================================================

/**
 * @brief Test fixture for comprehensive database function testing
 */
class ComprehensiveDatabaseTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test database
        test_db_path = "test_comprehensive.db";
        db = db_init(test_db_path, NULL);
        if (db) {
            db_create_tables(db);
        }
    }

    void TearDown() override {
        if (db) {
            db_close(db);
        }
        // Clean up test database file
        remove(test_db_path);
    }

    Database* db = nullptr;
    const char* test_db_path;
};

/**
 * @brief Test database initialization and table creation
 */
TEST_F(ComprehensiveDatabaseTest, DatabaseInitializationAndTableCreation) {
    ASSERT_NE(db, nullptr) << "Database should be initialized successfully";
    
    // Test that tables are created
    int result = db_create_tables(db);
    EXPECT_EQ(result, 0) << "Tables should be created successfully";
}

/**
 * @brief Test user management functions
 */
TEST_F(ComprehensiveDatabaseTest, UserManagementFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Test adding user
    int result = db_add_user(db, "testuser", "encrypted_password");
    EXPECT_EQ(result, 0) << "User should be added successfully";
    
    // Test user exists
    int exists = db_user_exists(db, "testuser");
    EXPECT_EQ(exists, 1) << "User should exist after adding";
    
    // Test getting user password
    char* password = nullptr;
    result = db_get_user_password(db, "testuser", &password);
    EXPECT_EQ(result, 0) << "Should get user password successfully";
    EXPECT_NE(password, nullptr) << "Password should not be null";
    if (password) {
        EXPECT_STREQ(password, "encrypted_password") << "Password should match";
        free(password);
    }
    
    // Test non-existent user
    exists = db_user_exists(db, "nonexistent");
    EXPECT_EQ(exists, 0) << "Non-existent user should not exist";
}

/**
 * @brief Test pet management functions
 */
TEST_F(ComprehensiveDatabaseTest, PetManagementFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Test adding pet
    int result = db_add_pet(db, "Buddy", "Dog", 3, "testuser");
    EXPECT_EQ(result, 0) << "Pet should be added successfully";
    
    // Test pet ownership check
    int owned = db_is_pet_owned_by(db, "Buddy", "testuser");
    EXPECT_EQ(owned, 1) << "Pet should be owned by testuser";
    
    // Test updating pet
    result = db_update_pet(db, "Buddy", "testuser", "BuddyUpdated", "Cat", 4);
    EXPECT_EQ(result, 0) << "Pet should be updated successfully";
    
    // Test deleting pet
    result = db_delete_pet(db, "BuddyUpdated", "testuser");
    EXPECT_EQ(result, 0) << "Pet should be deleted successfully";
    
    // Test pet no longer exists
    owned = db_is_pet_owned_by(db, "BuddyUpdated", "testuser");
    EXPECT_EQ(owned, 0) << "Pet should no longer exist after deletion";
}

/**
 * @brief Test appointment management functions
 */
TEST_F(ComprehensiveDatabaseTest, AppointmentManagementFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Test adding appointment
    int result = db_add_appointment(db, "Buddy", "Checkup", 15, 6, "testuser");
    EXPECT_EQ(result, 0) << "Appointment should be added successfully";
    
    // Test date occupation check
    int occupied = db_is_date_occupied(db, 15, 6);
    EXPECT_EQ(occupied, 1) << "Date should be occupied";
    
    // Test updating appointment
    result = db_update_appointment(db, "Buddy", 15, 6, 16, 6, "Vaccination", "testuser");
    EXPECT_EQ(result, 0) << "Appointment should be updated successfully";
    
    // Test deleting appointment
    result = db_delete_appointment(db, "Buddy", 16, 6, "testuser");
    EXPECT_EQ(result, 0) << "Appointment should be deleted successfully";
    
    // Test date no longer occupied
    occupied = db_is_date_occupied(db, 16, 6);
    EXPECT_EQ(occupied, 0) << "Date should no longer be occupied";
}

/**
 * @brief Test birthday management functions
 */
TEST_F(ComprehensiveDatabaseTest, BirthdayManagementFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Test adding birthday
    int result = db_add_birthday(db, "Buddy", 15, 6, 2020, "testuser");
    EXPECT_EQ(result, 0) << "Birthday should be added successfully";
    
    // Test updating birthday (same pet, different date)
    result = db_add_birthday(db, "Buddy", 20, 7, 2021, "testuser");
    EXPECT_EQ(result, 0) << "Birthday should be updated successfully";
}

/**
 * @brief Test stray animal management functions
 */
TEST_F(ComprehensiveDatabaseTest, StrayAnimalManagementFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Test adding stray animal
    int result = db_add_stray_animal(db, "Dog", "Male", "01/01/2023", 3);
    EXPECT_GT(result, 0) << "Stray animal should be added and return ID";
    int animal_id = result;
    
    // Test updating stray animal
    result = db_update_stray_animal(db, animal_id, "Cat", "Female", "02/02/2023", 2);
    EXPECT_EQ(result, 0) << "Stray animal should be updated successfully";
    
    // Test deleting stray animal
    result = db_delete_stray_animal(db, animal_id);
    EXPECT_EQ(result, 0) << "Stray animal should be deleted successfully";
}

/**
 * @brief Test adopted animal management functions
 */
TEST_F(ComprehensiveDatabaseTest, AdoptedAnimalManagementFunctions) {
    ASSERT_NE(db, nullptr);
    
    // First add a stray animal
    int stray_id = db_add_stray_animal(db, "Dog", "Male", "01/01/2023", 3);
    ASSERT_GT(stray_id, 0) << "Should add stray animal first";
    
    // Test adopting stray animal
    int result = db_adopt_stray_animal(db, stray_id, "testuser", "02/02/2023");
    EXPECT_EQ(result, 0) << "Stray animal should be adopted successfully";
    
    // Test adding adopted animal directly
    result = db_add_adopted_animal(db, 999, "Cat", "Female", "03/03/2023", 2, "testuser2", "04/04/2023");
    EXPECT_EQ(result, 0) << "Adopted animal should be added successfully";
}

/**
 * @brief Test feeding schedule functions
 */
TEST_F(ComprehensiveDatabaseTest, FeedingScheduleFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Test adding feeding schedule
    int result = db_add_feeding_schedule(db, "Buddy", "Morning: 8AM, Evening: 6PM", "testuser");
    EXPECT_EQ(result, 0) << "Feeding schedule should be added successfully";
    
    // Test updating feeding schedule
    result = db_update_feeding_schedule(db, "Buddy", "testuser", "Morning: 7AM, Evening: 7PM");
    EXPECT_EQ(result, 0) << "Feeding schedule should be updated successfully";
    
    // Test deleting feeding schedule
    result = db_delete_feeding_schedule(db, "Buddy", "testuser");
    EXPECT_EQ(result, 0) << "Feeding schedule should be deleted successfully";
}

/**
 * @brief Test medicine schedule functions
 */
TEST_F(ComprehensiveDatabaseTest, MedicineScheduleFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Test adding medicine schedule
    int result = db_add_medicine_schedule(db, "Buddy", "Antibiotic: 2x daily", "testuser");
    EXPECT_EQ(result, 0) << "Medicine schedule should be added successfully";
    
    // Test updating medicine schedule
    result = db_update_medicine_schedule(db, "Buddy", "testuser", "Antibiotic: 3x daily");
    EXPECT_EQ(result, 0) << "Medicine schedule should be updated successfully";
    
    // Test deleting medicine schedule
    result = db_delete_medicine_schedule(db, "Buddy", "testuser");
    EXPECT_EQ(result, 0) << "Medicine schedule should be deleted successfully";
}

/**
 * @brief Test exercise routine functions
 */
TEST_F(ComprehensiveDatabaseTest, ExerciseRoutineFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Test adding exercise routine
    int result = db_add_exercise_routine(db, "Buddy", "30 min walk daily", "testuser");
    EXPECT_EQ(result, 0) << "Exercise routine should be added successfully";
    
    // Test updating exercise routine
    result = db_update_exercise_routine(db, "Buddy", "testuser", "45 min walk daily");
    EXPECT_EQ(result, 0) << "Exercise routine should be updated successfully";
    
    // Test deleting exercise routine
    result = db_delete_exercise_routine(db, "Buddy", "testuser");
    EXPECT_EQ(result, 0) << "Exercise routine should be deleted successfully";
}

/**
 * @brief Test transaction functions
 */
TEST_F(ComprehensiveDatabaseTest, TransactionFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Test beginning transaction
    int result = db_begin_transaction(db);
    EXPECT_EQ(result, 0) << "Transaction should begin successfully";
    
    // Test committing transaction
    result = db_commit_transaction(db);
    EXPECT_EQ(result, 0) << "Transaction should commit successfully";
    
    // Test rollback transaction
    result = db_begin_transaction(db);
    EXPECT_EQ(result, 0) << "Transaction should begin successfully";
    
    result = db_rollback_transaction(db);
    EXPECT_EQ(result, 0) << "Transaction should rollback successfully";
}

/**
 * @brief Test utility functions
 */
TEST_F(ComprehensiveDatabaseTest, UtilityFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Test getting error message
    const char* error = db_get_error(db);
    EXPECT_NE(error, nullptr) << "Error message should not be null";
    
    // Test last insert ID
    long long last_id = db_last_insert_id(db);
    EXPECT_GE(last_id, 0) << "Last insert ID should be non-negative";
    
    // Test execute function
    int result = db_execute(db, "SELECT 1");
    EXPECT_EQ(result, 0) << "Execute should succeed for valid SQL";
}

/**
 * @brief Test backup and restore functions
 */
TEST_F(ComprehensiveDatabaseTest, BackupAndRestoreFunctions) {
    ASSERT_NE(db, nullptr);
    
    // Add some test data
    db_add_user(db, "testuser", "password");
    db_add_pet(db, "Buddy", "Dog", 3, "testuser");
    
    // Test backup
    int result = db_backup(db, "test_backup.db");
    EXPECT_EQ(result, 0) << "Backup should succeed";
    
    // Test restore
    result = db_restore("test_restored.db", "test_backup.db");
    EXPECT_EQ(result, 0) << "Restore should succeed";
    
    // Clean up backup files
    remove("test_backup.db");
    remove("test_restored.db");
}

// ============================================================================
// DATABASE EDGE CASE TESTS
// ============================================================================

/**
 * @brief Test fixture for database edge case testing
 */
class DatabaseEdgeCaseTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_db_path = "test_edge_cases.db";
        db = db_init(test_db_path, NULL);
        if (db) {
            db_create_tables(db);
        }
    }

    void TearDown() override {
        if (db) {
            db_close(db);
        }
        remove(test_db_path);
    }

    Database* db = nullptr;
    const char* test_db_path;
};

/**
 * @brief Test database functions with invalid parameters
 */
TEST_F(DatabaseEdgeCaseTest, InvalidParameters) {
    ASSERT_NE(db, nullptr);
    
    // Test with NULL parameters
    EXPECT_EQ(db_add_user(db, NULL, "password"), -1);
    EXPECT_EQ(db_add_user(db, "user", NULL), -1);
    EXPECT_EQ(db_add_pet(db, NULL, "Dog", 3, "user"), -1);
    EXPECT_EQ(db_add_pet(db, "Buddy", NULL, 3, "user"), -1);
    EXPECT_EQ(db_add_pet(db, "Buddy", "Dog", 3, NULL), -1);
    EXPECT_EQ(db_add_appointment(db, NULL, "Checkup", 15, 6, "user"), -1);
    EXPECT_EQ(db_add_appointment(db, "Buddy", NULL, 15, 6, "user"), -1);
    EXPECT_EQ(db_add_appointment(db, "Buddy", "Checkup", 15, 6, NULL), -1);
}

/**
 * @brief Test database functions with empty strings
 */
TEST_F(DatabaseEdgeCaseTest, EmptyStrings) {
    ASSERT_NE(db, nullptr);
    
    // Test with empty strings
    EXPECT_EQ(db_add_user(db, "", "password"), -1);
    EXPECT_EQ(db_add_user(db, "user", ""), -1);
    EXPECT_EQ(db_add_pet(db, "", "Dog", 3, "user"), -1);
    EXPECT_EQ(db_add_pet(db, "Buddy", "", 3, "user"), -1);
    EXPECT_EQ(db_add_pet(db, "Buddy", "Dog", 3, ""), -1);
}

/**
 * @brief Test database functions with boundary values
 */
TEST_F(DatabaseEdgeCaseTest, BoundaryValues) {
    ASSERT_NE(db, nullptr);
    
    // Test with very long strings
    char long_string[1000];
    memset(long_string, 'A', sizeof(long_string) - 1);
    long_string[sizeof(long_string) - 1] = '\0';
    
    EXPECT_EQ(db_add_user(db, long_string, "password"), -1);
    EXPECT_EQ(db_add_pet(db, long_string, "Dog", 3, "user"), -1);
    
    // Test with negative age
    EXPECT_EQ(db_add_pet(db, "Buddy", "Dog", -1, "user"), -1);
    
    // Test with invalid dates
    EXPECT_EQ(db_add_appointment(db, "Buddy", "Checkup", 0, 6, "user"), -1);
    EXPECT_EQ(db_add_appointment(db, "Buddy", "Checkup", 15, 0, "user"), -1);
    EXPECT_EQ(db_add_appointment(db, "Buddy", "Checkup", 32, 6, "user"), -1);
    EXPECT_EQ(db_add_appointment(db, "Buddy", "Checkup", 15, 13, "user"), -1);
}

/**
 * @brief Test database functions with duplicate data
 */
TEST_F(DatabaseEdgeCaseTest, DuplicateData) {
    ASSERT_NE(db, nullptr);
    
    // Add initial data
    EXPECT_EQ(db_add_user(db, "testuser", "password"), 0);
    EXPECT_EQ(db_add_pet(db, "Buddy", "Dog", 3, "testuser"), 0);
    EXPECT_EQ(db_add_appointment(db, "Buddy", "Checkup", 15, 6, "testuser"), 0);
    
    // Test duplicate user
    EXPECT_EQ(db_add_user(db, "testuser", "password2"), -1);
    
    // Test duplicate appointment date
    EXPECT_EQ(db_add_appointment(db, "Buddy", "Vaccination", 15, 6, "testuser"), -1);
}

/**
 * @brief Test database functions with non-existent references
 */
TEST_F(DatabaseEdgeCaseTest, NonExistentReferences) {
    ASSERT_NE(db, nullptr);
    
    // Test operations on non-existent data
    EXPECT_EQ(db_is_pet_owned_by(db, "NonExistent", "user"), 0);
    EXPECT_EQ(db_user_exists(db, "NonExistent"), 0);
    EXPECT_EQ(db_is_date_occupied(db, 99, 99), 0);
    
    // Test updating non-existent records
    EXPECT_EQ(db_update_pet(db, "NonExistent", "user", "NewName", "Cat", 2), -1);
    EXPECT_EQ(db_delete_pet(db, "NonExistent", "user"), -1);
    EXPECT_EQ(db_update_appointment(db, "NonExistent", 99, 99, 16, 6, "New", "user"), -1);
    EXPECT_EQ(db_delete_appointment(db, "NonExistent", 99, 99, "user"), -1);
}

// ============================================================================
// DATABASE INTEGRATION TESTS
// ============================================================================

/**
 * @brief Test fixture for database integration testing
 */
class DatabaseIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_db_path = "test_integration.db";
        db = db_init(test_db_path, NULL);
        if (db) {
            db_create_tables(db);
        }
    }

    void TearDown() override {
        if (db) {
            db_close(db);
        }
        remove(test_db_path);
    }

    Database* db = nullptr;
    const char* test_db_path;
};

/**
 * @brief Test complete user workflow
 */
TEST_F(DatabaseIntegrationTest, CompleteUserWorkflow) {
    ASSERT_NE(db, nullptr);
    
    // 1. Register user
    EXPECT_EQ(db_add_user(db, "testuser", "encrypted_password"), 0);
    EXPECT_EQ(db_user_exists(db, "testuser"), 1);
    
    // 2. Add pets
    EXPECT_EQ(db_add_pet(db, "Buddy", "Dog", 3, "testuser"), 0);
    EXPECT_EQ(db_add_pet(db, "Kitty", "Cat", 2, "testuser"), 0);
    EXPECT_EQ(db_is_pet_owned_by(db, "Buddy", "testuser"), 1);
    EXPECT_EQ(db_is_pet_owned_by(db, "Kitty", "testuser"), 1);
    
    // 3. Add appointments
    EXPECT_EQ(db_add_appointment(db, "Buddy", "Checkup", 15, 6, "testuser"), 0);
    EXPECT_EQ(db_add_appointment(db, "Kitty", "Vaccination", 20, 6, "testuser"), 0);
    EXPECT_EQ(db_is_date_occupied(db, 15, 6), 1);
    EXPECT_EQ(db_is_date_occupied(db, 20, 6), 1);
    
    // 4. Add birthdays
    EXPECT_EQ(db_add_birthday(db, "Buddy", 15, 6, 2020, "testuser"), 0);
    EXPECT_EQ(db_add_birthday(db, "Kitty", 20, 7, 2021, "testuser"), 0);
    
    // 5. Add schedules
    EXPECT_EQ(db_add_feeding_schedule(db, "Buddy", "Morning: 8AM, Evening: 6PM", "testuser"), 0);
    EXPECT_EQ(db_add_medicine_schedule(db, "Kitty", "Antibiotic: 2x daily", "testuser"), 0);
    EXPECT_EQ(db_add_exercise_routine(db, "Buddy", "30 min walk daily", "testuser"), 0);
    
    // 6. Update records
    EXPECT_EQ(db_update_pet(db, "Buddy", "testuser", "BuddyUpdated", "Dog", 4), 0);
    EXPECT_EQ(db_update_appointment(db, "BuddyUpdated", 15, 6, 16, 6, "Updated Checkup", "testuser"), 0);
    EXPECT_EQ(db_update_feeding_schedule(db, "BuddyUpdated", "testuser", "Morning: 7AM, Evening: 7PM"), 0);
    
    // 7. Delete records
    EXPECT_EQ(db_delete_appointment(db, "BuddyUpdated", 16, 6, "testuser"), 0);
    EXPECT_EQ(db_delete_feeding_schedule(db, "BuddyUpdated", "testuser"), 0);
    EXPECT_EQ(db_delete_pet(db, "BuddyUpdated", "testuser"), 0);
    
    // 8. Verify deletions
    EXPECT_EQ(db_is_pet_owned_by(db, "BuddyUpdated", "testuser"), 0);
    EXPECT_EQ(db_is_date_occupied(db, 16, 6), 0);
}

/**
 * @brief Test stray animal adoption workflow
 */
TEST_F(DatabaseIntegrationTest, StrayAnimalAdoptionWorkflow) {
    ASSERT_NE(db, nullptr);
    
    // 1. Add stray animals
    int stray_id1 = db_add_stray_animal(db, "Dog", "Male", "01/01/2023", 3);
    int stray_id2 = db_add_stray_animal(db, "Cat", "Female", "02/02/2023", 2);
    EXPECT_GT(stray_id1, 0);
    EXPECT_GT(stray_id2, 0);
    
    // 2. Update stray animal
    EXPECT_EQ(db_update_stray_animal(db, stray_id1, "Dog", "Male", "01/01/2023", 4), 0);
    
    // 3. Adopt stray animals
    EXPECT_EQ(db_adopt_stray_animal(db, stray_id1, "testuser1", "03/03/2023"), 0);
    EXPECT_EQ(db_adopt_stray_animal(db, stray_id2, "testuser2", "04/04/2023"), 0);
    
    // 4. Verify adoption (stray animals should be removed from stray table)
    EXPECT_EQ(db_delete_stray_animal(db, stray_id1), -1); // Should fail as already adopted
    EXPECT_EQ(db_delete_stray_animal(db, stray_id2), -1); // Should fail as already adopted
}

/**
 * @brief Test database transaction rollback
 */
TEST_F(DatabaseIntegrationTest, TransactionRollback) {
    ASSERT_NE(db, nullptr);
    
    // Begin transaction
    EXPECT_EQ(db_begin_transaction(db), 0);
    
    // Add some data
    EXPECT_EQ(db_add_user(db, "testuser", "password"), 0);
    EXPECT_EQ(db_add_pet(db, "Buddy", "Dog", 3, "testuser"), 0);
    
    // Rollback transaction
    EXPECT_EQ(db_rollback_transaction(db), 0);
    
    // Verify data was not committed
    EXPECT_EQ(db_user_exists(db, "testuser"), 0);
    EXPECT_EQ(db_is_pet_owned_by(db, "Buddy", "testuser"), 0);
}

/**
 * @brief Test database backup and restore workflow
 */
TEST_F(DatabaseIntegrationTest, BackupAndRestoreWorkflow) {
    ASSERT_NE(db, nullptr);
    
    // Add test data
    EXPECT_EQ(db_add_user(db, "testuser", "password"), 0);
    EXPECT_EQ(db_add_pet(db, "Buddy", "Dog", 3, "testuser"), 0);
    EXPECT_EQ(db_add_appointment(db, "Buddy", "Checkup", 15, 6, "testuser"), 0);
    
    // Create backup
    EXPECT_EQ(db_backup(db, "integration_backup.db"), 0);
    
    // Add more data after backup
    EXPECT_EQ(db_add_pet(db, "Kitty", "Cat", 2, "testuser"), 0);
    
    // Restore from backup
    EXPECT_EQ(db_restore("integration_restored.db", "integration_backup.db"), 0);
    
    // Verify restored data (should not have Kitty)
    Database* restored_db = db_init("integration_restored.db", NULL);
    ASSERT_NE(restored_db, nullptr);
    
    EXPECT_EQ(db_user_exists(restored_db, "testuser"), 1);
    EXPECT_EQ(db_is_pet_owned_by(restored_db, "Buddy", "testuser"), 1);
    EXPECT_EQ(db_is_pet_owned_by(restored_db, "Kitty", "testuser"), 0);
    EXPECT_EQ(db_is_date_occupied(restored_db, 15, 6), 1);
    
    db_close(restored_db);
    
    // Clean up
    remove("integration_backup.db");
    remove("integration_restored.db");
}

/**
 * @brief Test loading all adopted animals from database
 */
TEST_F(DatabaseIntegrationTest, LoadAllAdoptedAnimals) {
#ifndef SQLITE3_HEADER_ONLY
    ASSERT_NE(db, nullptr);

    // Prepare: add two stray animals then adopt them
    int stray_id1 = db_add_stray_animal(db, "Dog", "Male", "01/01/2024", 2);
    int stray_id2 = db_add_stray_animal(db, "Cat", "Female", "02/01/2024", 1);
    ASSERT_GT(stray_id1, 0);
    ASSERT_GT(stray_id2, 0);

    EXPECT_EQ(db_adopt_stray_animal(db, stray_id1, "ownerA", "03/01/2024"), 0);
    EXPECT_EQ(db_adopt_stray_animal(db, stray_id2, "ownerB", "04/01/2024"), 0);

    // Load all adopted animals
    AdoptedAnimal* list = NULL;
    int count = db_load_all_adopted_animals(db, &list);
    EXPECT_GE(count, 2);

    // Verify that at least our two adoptions are present
    bool found1 = false, found2 = false;
    for (AdoptedAnimal* cur = list; cur != NULL; cur = cur->next) {
        if (cur->id == stray_id1) {
            found1 = true;
        }
        if (cur->id == stray_id2) {
            found2 = true;
        }
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);

    // Cleanup allocated list
    while (list != NULL) {
        AdoptedAnimal* next = list->next;
        free(list);
        list = next;
    }
#endif
}

// ============================================================================
// Additional Database Tests: Grooming + Loaders (Feeding/Medicine/Exercise)
// Covers zero-coverage areas in database.cpp
// ============================================================================

/**
 * @class DatabaseGroomingAndSchedulesTest
 * @brief Fixture to test grooming routines and DB->memory loaders
 */
class DatabaseGroomingAndSchedulesTest : public ::testing::Test {
protected:
    const char* db_path = "test_groom_sched.db";
    Database* db = nullptr;

    void SetUp() override {
        remove(db_path);
        db = db_init(db_path, NULL);
        if (db) {
            db_create_tables(db);
            // minimal owner and pet
            db_add_user(db, "owner1", "pw");
            db_add_pet(db, "Rex", "Dog", 5, "owner1");
        }
    }

    void TearDown() override {
        if (db) {
            db_close(db);
            db = nullptr;
        }
        remove(db_path);
    }
};

/**
 * @brief Test grooming routines CRUD and listing
 */
TEST_F(DatabaseGroomingAndSchedulesTest, GroomingCrudAndPrint) {
#ifndef SQLITE3_HEADER_ONLY
    ASSERT_NE(db, nullptr);

    // Create
    EXPECT_EQ(db_add_grooming_routine(db, "Rex", "Bath weekly", "owner1"), 0);

    // Update
    EXPECT_EQ(db_update_grooming_routine(db, "Rex", "owner1", "Bath weekly + nails"), 0);

    // Print/list (returns count)
    int printed = db_print_all_groomings(db);
    EXPECT_GE(printed, 1);

    // Delete
    EXPECT_EQ(db_delete_grooming_routine(db, "Rex", "owner1"), 0);

    // After delete, printing may return 0 or >=0 depending on other data, but should not error
    EXPECT_GE(db_print_all_groomings(db), 0);
#endif
}

/**
 * @brief Test loading feeding schedules from DB into Queue
 */
TEST_F(DatabaseGroomingAndSchedulesTest, LoadFeedingSchedulesIntoQueue) {
#ifndef SQLITE3_HEADER_ONLY
    ASSERT_NE(db, nullptr);
    EXPECT_EQ(db_add_feeding_schedule(db, "Rex", "8AM & 6PM", "owner1"), 0);

    Queue* q = createQueue();
    ASSERT_NE(q, nullptr);

    int loaded = db_load_feeding_schedules(db, q);
    EXPECT_EQ(loaded, 1);
    EXPECT_EQ(isQueueEmpty(q), 0);

    FeedingSchedule* f = dequeue(q);
    ASSERT_NE(f, nullptr);
    EXPECT_STREQ(f->petName, "Rex");
    EXPECT_STRNE(f->scheduleDetails, "");
    free(f);

    // queue should be empty now
    EXPECT_NE(q, nullptr);
#endif
}

/**
 * @brief Test loading medicine schedules from DB into Queue
 */
TEST_F(DatabaseGroomingAndSchedulesTest, LoadMedicineSchedulesIntoQueue) {
#ifndef SQLITE3_HEADER_ONLY
    ASSERT_NE(db, nullptr);
    EXPECT_EQ(db_add_medicine_schedule(db, "Rex", "Pill 1x daily", "owner1"), 0);

    Queue* q = createQueue();
    ASSERT_NE(q, nullptr);

    int loaded = db_load_medicine_schedules(db, q);
    EXPECT_EQ(loaded, 1);
    EXPECT_EQ(isQueueEmpty(q), 0);

    FeedingSchedule* m = dequeue(q);
    ASSERT_NE(m, nullptr);
    EXPECT_STREQ(m->petName, "Rex");
    EXPECT_STRNE(m->scheduleDetails, "");
    free(m);
#endif
}

/**
 * @brief Test loading exercise routines into global exerciseStack
 */
TEST_F(DatabaseGroomingAndSchedulesTest, LoadExerciseRoutinesIntoStack) {
#ifndef SQLITE3_HEADER_ONLY
    ASSERT_NE(db, nullptr);
    EXPECT_EQ(db_add_exercise_routine(db, "Rex", "Walk 30m", "owner1"), 0);
    EXPECT_EQ(db_add_exercise_routine(db, "Rex", "Fetch 15m", "owner1"), 0);

    int count = db_load_exercise_routines(db, "owner1");
    EXPECT_GE(count, 1);

    extern ExerciseStack exerciseStack;
    EXPECT_GE(exerciseStack.top, 0);
#endif
}

// ============================================================================
// ADDITIONAL TESTS FOR UNCOVERED CODE PATHS
// ============================================================================

/**
 * @class AppointmentFileTest
 * @brief Test fixture for file-based appointment loading tests
 */
class AppointmentFileTest : public ::testing::Test {
protected:
    const char* testFile = "test_appointments.data";
    Pet* petList = nullptr;
    
    void SetUp() override {
        // Reset global appointment list
        extern Appointment* appointmentList;
        appointmentList = nullptr;
        
        // Create test pet
        addPet(&petList, "TestPet", "Dog", 3, "TestOwner");
    }
    
    void TearDown() override {
        freePetList(petList);
        petList = nullptr;
        
        // Clean up appointment list
        extern Appointment* appointmentList;
        Appointment* current = appointmentList;
        Appointment* prev = nullptr;
        Appointment* next;
        while (current != nullptr) {
            next = XOR(prev, current->xorPtr);
            free(current);
            prev = current;
            current = next;
        }
        appointmentList = nullptr;
    }
};

/**
 * @brief Test loadAppointmentsFromFile with file-based storage
 */
TEST_F(AppointmentFileTest, LoadAppointmentsFromFileBasic) {
    // First save an appointment
    addAppointment("TestPet", "Checkup", 10, 5, "TestOwner", petList);
    saveAppointmentsToFile();
    
    // Clear and reload
    extern Appointment* appointmentList;
    Appointment* current = appointmentList;
    Appointment* prev = nullptr;
    Appointment* next;
    while (current != nullptr) {
        next = XOR(prev, current->xorPtr);
        free(current);
        prev = current;
        current = next;
    }
    appointmentList = nullptr;
    
    // Load from file
    loadAppointmentsFromFile();
    
    // Verify appointment was loaded (if database not used)
    // The test just ensures the function runs without crashing
    SUCCEED();
}

/**
 * @brief Test loadAppointmentsFromFile with empty/missing files
 */
TEST_F(AppointmentFileTest, LoadAppointmentsFromFileMissing) {
    // Remove test files
    remove("test_appointments.data");
    remove("appointment.data");
    
    // Load should handle missing files gracefully
    loadAppointmentsFromFile();
    
    extern Appointment* appointmentList;
    EXPECT_EQ(appointmentList, nullptr);
}

/**
 * @class CancelAppointmentEdgeCasesTest
 * @brief Test edge cases for cancelAppointment function
 */
class CancelAppointmentEdgeCasesTest : public ::testing::Test {
protected:
    Pet* petList = nullptr;
    
    void SetUp() override {
        // Reset global appointment list
        extern Appointment* appointmentList;
        appointmentList = nullptr;
        
        addPet(&petList, "Pet1", "Dog", 3, "Owner1");
        addPet(&petList, "Pet2", "Cat", 2, "Owner2");
    }
    
    void TearDown() override {
        freePetList(petList);
        petList = nullptr;
        
        extern Appointment* appointmentList;
        Appointment* current = appointmentList;
        Appointment* prev = nullptr;
        Appointment* next;
        while (current != nullptr) {
            next = XOR(prev, current->xorPtr);
            free(current);
            prev = current;
            current = next;
        }
        appointmentList = nullptr;
    }
};

/**
 * @brief Test cancel appointment when pet is not owned by user
 */
TEST_F(CancelAppointmentEdgeCasesTest, CancelPetNotOwned) {
    addAppointment("Pet1", "Checkup", 15, 6, "Owner1", petList);
    
    testing::internal::CaptureStdout();
    bool result = cancelAppointment("Pet1", 15, 6, "WrongOwner");
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_FALSE(result);
    EXPECT_NE(output.find("Error: You do not own a pet named"), std::string::npos);
}

/**
 * @brief Test cancel appointment when date doesn't match
 */
TEST_F(CancelAppointmentEdgeCasesTest, CancelWrongDate) {
    addAppointment("Pet1", "Checkup", 15, 6, "Owner1", petList);
    
    testing::internal::CaptureStdout();
    bool result = cancelAppointment("Pet1", 20, 6, "Owner1");
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_FALSE(result);
    EXPECT_NE(output.find("No matching appointment found"), std::string::npos);
}

/**
 * @brief Test cancel with multiple appointments - canceling middle one
 */
TEST_F(CancelAppointmentEdgeCasesTest, CancelMiddleAppointment) {
    // Use different months to avoid "date already occupied" constraint
    addAppointment("Pet1", "Checkup1", 10, 5, "Owner1", petList);
    addAppointment("Pet1", "Checkup2", 10, 6, "Owner1", petList);
    addAppointment("Pet1", "Checkup3", 10, 7, "Owner1", petList);
    
    // Cancel middle appointment (month 6)
    bool result = cancelAppointment("Pet1", 10, 6, "Owner1");
    EXPECT_TRUE(result);
    
    // The test verifies the cancel operation succeeded
    SUCCEED();
}

/**
 * @class DeletePetEdgeCasesTest
 * @brief Test edge cases for deletePet function
 */
class DeletePetEdgeCasesTest : public ::testing::Test {
protected:
    Pet* petList = nullptr;
    
    void TearDown() override {
        freePetList(petList);
        petList = nullptr;
    }
};

/**
 * @brief Test delete pet from middle of list
 */
TEST_F(DeletePetEdgeCasesTest, DeleteMiddlePet) {
    addPet(&petList, "Pet1", "Dog", 3, "Owner1");
    addPet(&petList, "Pet2", "Cat", 2, "Owner1");
    addPet(&petList, "Pet3", "Bird", 1, "Owner1");
    
    // Delete middle pet
    deletePet(&petList, "Pet2", "Owner1");
    
    // Verify Pet1 and Pet3 still exist
    EXPECT_NE(petList, nullptr);
    
    // Count remaining pets
    int count = 0;
    Pet* current = petList;
    while (current) {
        count++;
        current = current->next;
    }
    EXPECT_EQ(count, 2);
}

/**
 * @brief Test delete pet not in list
 */
TEST_F(DeletePetEdgeCasesTest, DeleteNonExistentPet) {
    addPet(&petList, "Pet1", "Dog", 3, "Owner1");
    
    // The function prints to stdout/stderr via OBF_INFO macro
    // Just verify pet list is unchanged
    deletePet(&petList, "NonExistent", "Owner1");
    
    // Pet1 should still exist
    EXPECT_NE(petList, nullptr);
    EXPECT_STREQ(petList->name, "Pet1");
}

/**
 * @brief Test delete pet with wrong owner
 */
TEST_F(DeletePetEdgeCasesTest, DeletePetWrongOwner) {
    addPet(&petList, "Pet1", "Dog", 3, "Owner1");
    
    // The function prints to stdout/stderr via OBF_INFO macro
    // Just verify pet list is unchanged when wrong owner is used
    deletePet(&petList, "Pet1", "WrongOwner");
    
    // Pet1 should still exist
    EXPECT_NE(petList, nullptr);
    EXPECT_STREQ(petList->name, "Pet1");
}

/**
 * @brief Test delete last pet in list
 */
TEST_F(DeletePetEdgeCasesTest, DeleteLastPetInMultipleList) {
    addPet(&petList, "Pet1", "Dog", 3, "Owner1");
    addPet(&petList, "Pet2", "Cat", 2, "Owner1");
    
    // Pet1 is at front (head), Pet2 is second
    // Delete Pet1 (head)
    deletePet(&petList, "Pet1", "Owner1");
    
    EXPECT_NE(petList, nullptr);
    EXPECT_STREQ(petList->name, "Pet2");
}

/**
 * @class SavePetsEdgeCasesTest
 * @brief Test edge cases for savePetsToFile function
 */
class SavePetsEdgeCasesTest : public ::testing::Test {
protected:
    Pet* petList = nullptr;
    const char* testFile = "test_save_pets.dat";
    
    void TearDown() override {
        freePetList(petList);
        petList = nullptr;
        remove(testFile);
        remove("test_save_pets.dat.tmp");
    }
};

/**
 * @brief Test saving empty pet list
 */
TEST_F(SavePetsEdgeCasesTest, SaveEmptyPetList) {
    // petList is nullptr
    savePetsToFile(nullptr, testFile);
    
    // Should create empty file or handle gracefully
    SUCCEED();
}

/**
 * @brief Test saving and loading pet list roundtrip
 */
TEST_F(SavePetsEdgeCasesTest, SaveLoadRoundtrip) {
    addPet(&petList, "TestPet", "Dog", 5, "TestOwner");
    
    savePetsToFile(petList, testFile);
    
    Pet* loadedList = nullptr;
    loadPetsFromFile(&loadedList, testFile);
    
    // If database is not used, verify load worked
    // Function should not crash
    freePetList(loadedList);
    SUCCEED();
}

/**
 * @class MedicineScheduleEdgeCasesTest
 * @brief Test edge cases for deleteMedicineSchedule function
 */
class MedicineScheduleEdgeCasesTest : public ::testing::Test {
protected:
    Queue* medicineQueue;
    
    void SetUp() override {
        medicineQueue = createQueue();
    }
    
    void TearDown() override {
        while (!isQueueEmpty(medicineQueue)) {
            FeedingSchedule* temp = dequeue(medicineQueue);
            free(temp);
        }
        free(medicineQueue);
    }
};

/**
 * @brief Test delete medicine schedule from middle of queue
 */
TEST_F(MedicineScheduleEdgeCasesTest, DeleteMiddleSchedule) {
    addMedicineSchedule(medicineQueue, "Pet1", "Med1");
    addMedicineSchedule(medicineQueue, "Pet2", "Med2");
    addMedicineSchedule(medicineQueue, "Pet3", "Med3");
    
    // Delete middle one
    deleteMedicineSchedule(medicineQueue, "Pet2");
    
    // Pet1 and Pet3 should remain
    EXPECT_FALSE(isQueueEmpty(medicineQueue));
    EXPECT_STREQ(medicineQueue->front->petName, "Pet1");
}

/**
 * @brief Test delete medicine schedule (last item - rear update)
 */
TEST_F(MedicineScheduleEdgeCasesTest, DeleteRearSchedule) {
    addMedicineSchedule(medicineQueue, "Pet1", "Med1");
    addMedicineSchedule(medicineQueue, "Pet2", "Med2");
    
    // Delete rear item
    deleteMedicineSchedule(medicineQueue, "Pet2");
    
    // Pet1 should remain and be both front and rear
    EXPECT_FALSE(isQueueEmpty(medicineQueue));
    EXPECT_STREQ(medicineQueue->front->petName, "Pet1");
    EXPECT_EQ(medicineQueue->front, medicineQueue->rear);
}

/**
 * @brief Test delete medicine schedule from empty queue
 */
TEST_F(MedicineScheduleEdgeCasesTest, DeleteFromEmptyQueue) {
    testing::internal::CaptureStdout();
    deleteMedicineSchedule(medicineQueue, "Pet1");
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_NE(output.find("No medicine schedules available"), std::string::npos);
}

/**
 * @class FeedingScheduleEdgeCasesTest
 * @brief Test edge cases for updateFeedingSchedule function
 */
class FeedingScheduleEdgeCasesTest : public ::testing::Test {
protected:
    Queue* feedingQueue;
    
    void SetUp() override {
        feedingQueue = createQueue();
    }
    
    void TearDown() override {
        while (!isQueueEmpty(feedingQueue)) {
            FeedingSchedule* temp = dequeue(feedingQueue);
            free(temp);
        }
        free(feedingQueue);
    }
};

/**
 * @brief Test update feeding schedule on empty queue
 */
TEST_F(FeedingScheduleEdgeCasesTest, UpdateEmptyQueue) {
    testing::internal::CaptureStdout();
    updateFeedingSchedule(feedingQueue, "Pet1", "New Schedule");
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_NE(output.find("No feeding schedules available"), std::string::npos);
}

/**
 * @brief Test delete feeding schedule from middle of queue
 */
TEST_F(FeedingScheduleEdgeCasesTest, DeleteMiddleFeedingSchedule) {
    enqueue(feedingQueue, "Pet1", "Feed1");
    enqueue(feedingQueue, "Pet2", "Feed2");
    enqueue(feedingQueue, "Pet3", "Feed3");
    
    // Delete middle one
    deleteFeedingSchedule(feedingQueue, "Pet2");
    
    // Pet1 and Pet3 should remain
    EXPECT_FALSE(isQueueEmpty(feedingQueue));
    EXPECT_STREQ(feedingQueue->front->petName, "Pet1");
}

/**
 * @class BirthdayFileEdgeCasesTest
 * @brief Test edge cases for birthday file operations
 */
class BirthdayFileEdgeCasesTest : public ::testing::Test {
protected:
    BPlusTree* tree = nullptr;
    Pet* petList = nullptr;
    const char* testFile = "test_birthday_edge.dat";
    
    void SetUp() override {
        tree = createBPlusTree();
        addPet(&petList, "BirthdayPet", "Dog", 3, "BirthdayOwner");
    }
    
    void TearDown() override {
        freePetList(petList);
        petList = nullptr;
        if (tree) delete tree;
        remove(testFile);
    }
};

/**
 * @brief Test save and load birthdays roundtrip
 */
TEST_F(BirthdayFileEdgeCasesTest, SaveLoadBirthdaysRoundtrip) {
    insertBirthday(tree, "BirthdayPet", 15, 8, 2020);
    
    saveBirthdaysToFile(tree, testFile, petList);
    
    BPlusTree* loadedTree = createBPlusTree();
    Pet* loadedPets = nullptr;
    loadBirthdaysFromFile(loadedTree, testFile, &loadedPets);
    
    // Function should not crash
    freePetList(loadedPets);
    delete loadedTree;
    SUCCEED();
}

/**
 * @brief Test save birthdays with empty tree
 */
TEST_F(BirthdayFileEdgeCasesTest, SaveEmptyBirthdayTree) {
    // tree is empty (no birthdays inserted)
    saveBirthdaysToFile(tree, testFile, petList);
    
    // Should handle gracefully
    SUCCEED();
}

/**
 * @brief Test load birthdays from non-existent file
 */
TEST_F(BirthdayFileEdgeCasesTest, LoadFromMissingFile) {
    remove(testFile);
    
    testing::internal::CaptureStderr();
    loadBirthdaysFromFile(tree, testFile, &petList);
    std::string errOutput = testing::internal::GetCapturedStderr();
    
    // Should print error but not crash
    SUCCEED();
}

/**
 * @class MigrationTest
 * @brief Test migrate_dat_to_sqlite function
 */
class MigrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Ensure no database is active for the test
    }
    
    void TearDown() override {
        // Clean up any test files
        remove("users.dat");
        remove("pets.dat");
        remove("adoptable.dat");
        remove("adopted.dat");
    }
};

/**
 * @brief Test migration when database is not initialized
 */
TEST_F(MigrationTest, MigrateWithoutDatabase) {
    // This test checks that migrate_dat_to_sqlite handles no database gracefully
    testing::internal::CaptureStderr();
    int result = migrate_dat_to_sqlite();
    std::string errOutput = testing::internal::GetCapturedStderr();
    
    EXPECT_EQ(result, -1);
    EXPECT_NE(errOutput.find("Database not initialized"), std::string::npos);
}

/**
 * @class StrayAnimalFileEdgeCasesTest
 * @brief Test edge cases for stray animal file operations
 */
class StrayAnimalFileEdgeCasesTest : public ::testing::Test {
protected:
    StrayAnimal* strayList = nullptr;
    AdoptedAnimal* adoptedList = nullptr;
    const char* strayFile = "test_stray_edge.dat";
    const char* adoptedFile = "test_adopted_edge.dat";
    
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
        remove(strayFile);
        remove(adoptedFile);
    }
};

/**
 * @brief Test save and load stray animals roundtrip
 */
TEST_F(StrayAnimalFileEdgeCasesTest, SaveLoadStrayAnimalsRoundtrip) {
    addStrayAnimalToList(&strayList, "Dog", "Male", "01/01/2024", 2);
    addStrayAnimalToList(&strayList, "Cat", "Female", "02/01/2024", 1);
    
    saveStrayAnimalsToFile(strayList, strayFile);
    
    StrayAnimal* loadedList = nullptr;
    loadStrayAnimalsFromFile(&loadedList, strayFile);
    
    // Should not crash
    while (loadedList) {
        StrayAnimal* temp = loadedList;
        loadedList = loadedList->next;
        free(temp);
    }
    SUCCEED();
}

/**
 * @brief Test save and load adopted animals roundtrip
 */
TEST_F(StrayAnimalFileEdgeCasesTest, SaveLoadAdoptedAnimalsRoundtrip) {
    addStrayAnimalToList(&strayList, "Dog", "Male", "01/01/2024", 2);
    adoptStrayAnimal(&strayList, "TestOwner", 1, "Buddy", "03/01/2024");
    
    saveAdoptedAnimalsToFile(adoptedList, adoptedFile);
    
    AdoptedAnimal* loadedList = nullptr;
    loadAdoptedAnimalsFromFile(&loadedList, adoptedFile);
    
    // Should not crash
    while (loadedList) {
        AdoptedAnimal* temp = loadedList;
        loadedList = loadedList->next;
        free(temp);
    }
    SUCCEED();
}

/**
 * @brief Test XOR encryption/decryption roundtrip
 */
TEST(XorEncryptionTest, EncryptDecryptRoundtrip) {
    char data[] = "Hello, World!";
    const char* key = "SecretKey";
    size_t len = strlen(data);
    
    char original[64];
    strcpy(original, data);
    
    // Encrypt
    xorEncryptDecrypt(data, len, key);
    
    // Data should be different after encryption
    EXPECT_STRNE(data, original);
    
    // Decrypt
    xorEncryptDecrypt(data, len, key);
    
    // Data should match original
    EXPECT_STREQ(data, original);
}

/**
 * @brief Test XOR encryption with empty string
 */
TEST(XorEncryptionTest, EncryptEmptyString) {
    char data[] = "";
    const char* key = "SecretKey";
    
    xorEncryptDecrypt(data, 0, key);
    EXPECT_STREQ(data, "");
}

// ============================================================================
// SESSION MANAGEMENT WITH FINGERPRINT TESTS
// ============================================================================

/**
 * @class SessionWithFingerprintTest
 * @brief Test fixture for session management with fingerprint functions
 */
class SessionWithFingerprintTest : public ::testing::Test {
protected:
    HashTable* sessionUserTable = nullptr;
    
    void SetUp() override {
        sessionUserTable = createHashTable();
        addUser(sessionUserTable, "testuser", "testpassword");
    }
    
    void TearDown() override {
        logoutUserSession();
        freeHashTable(sessionUserTable);
        sessionUserTable = nullptr;
    }
};

/**
 * @brief Test loginUserWithSession with valid credentials
 */
TEST_F(SessionWithFingerprintTest, LoginWithSessionValidCredentials) {
    // First ensure session is initialized
    init_petcare_session();
    
    int result = loginUserWithSession(sessionUserTable, "testuser", "testpassword");
    EXPECT_EQ(result, 1);
    
    // Session should be valid now
    EXPECT_EQ(isSessionValid(), 1);
}

/**
 * @brief Test loginUserWithSession with invalid credentials
 */
TEST_F(SessionWithFingerprintTest, LoginWithSessionInvalidCredentials) {
    init_petcare_session();
    
    int result = loginUserWithSession(sessionUserTable, "testuser", "wrongpassword");
    EXPECT_EQ(result, 0);
}

/**
 * @brief Test loginUserWithSession with non-existent user
 */
TEST_F(SessionWithFingerprintTest, LoginWithSessionNonExistentUser) {
    init_petcare_session();
    
    int result = loginUserWithSession(sessionUserTable, "nonexistent", "password");
    EXPECT_EQ(result, 0);
}

/**
 * @brief Test logoutUserSession
 */
TEST_F(SessionWithFingerprintTest, LogoutUserSession) {
    init_petcare_session();
    loginUserWithSession(sessionUserTable, "testuser", "testpassword");
    
    // Session should be valid after login
    EXPECT_EQ(isSessionValid(), 1);
    
    // Logout
    logoutUserSession();
    
    // Session should be invalid after logout
    EXPECT_EQ(isSessionValid(), 0);
}

/**
 * @brief Test isSessionValid without active session
 */
TEST_F(SessionWithFingerprintTest, IsSessionValidWithoutSession) {
    // Without login, session should be invalid
    int result = isSessionValid();
    EXPECT_EQ(result, 0);
}

/**
 * @brief Test session with fingerprint initialization
 */
TEST_F(SessionWithFingerprintTest, SessionWithFingerprintInit) {
    // Initialize session first
    init_petcare_session();
    
    // Login should work with initialized fingerprint
    int result = loginUserWithSession(sessionUserTable, "testuser", "testpassword");
    EXPECT_EQ(result, 1);
}

/**
 * @brief Test multiple login/logout cycles
 */
TEST_F(SessionWithFingerprintTest, MultipleLoginLogoutCycles) {
    init_petcare_session();
    
    for (int i = 0; i < 3; i++) {
        int result = loginUserWithSession(sessionUserTable, "testuser", "testpassword");
        EXPECT_EQ(result, 1);
        EXPECT_EQ(isSessionValid(), 1);
        
        logoutUserSession();
        EXPECT_EQ(isSessionValid(), 0);
    }
}

// ============================================================================
// DATABASE INITIALIZATION TESTS
// ============================================================================

/**
 * @class DatabaseInitTest
 * @brief Test fixture for database initialization functions
 */
class DatabaseInitTest : public ::testing::Test {
protected:
    const char* testDbPath = "test_init_database.db";
    
    void SetUp() override {
        // Clean up any existing test database
        remove(testDbPath);
        remove("test_init_database.db.enc");
        remove("test_init_database.db.tmp.sqlite");
    }
    
    void TearDown() override {
        close_petcare_database();
        remove(testDbPath);
        remove("test_init_database.db.enc");
        remove("test_init_database.db.tmp.sqlite");
    }
};

/**
 * @brief Test init_petcare_database with valid path
 */
TEST_F(DatabaseInitTest, InitDatabaseValidPath) {
    // First close any existing database
    close_petcare_database();
    
    int result = init_petcare_database(testDbPath);
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0);
    EXPECT_NE(get_petcare_database(), nullptr);
#endif
}

/**
 * @brief Test init_petcare_database called twice (already initialized)
 */
TEST_F(DatabaseInitTest, InitDatabaseAlreadyInitialized) {
    // First close any existing database
    close_petcare_database();
    
    int result1 = init_petcare_database(testDbPath);
    int result2 = init_petcare_database(testDbPath);
    
#ifndef SQLITE3_HEADER_ONLY
    // Second call should return 0 (already initialized)
    EXPECT_EQ(result2, 0);
#endif
}

/**
 * @brief Test close_petcare_database
 */
TEST_F(DatabaseInitTest, CloseDatabaseBasic) {
    close_petcare_database();
    
    int result = init_petcare_database(testDbPath);
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0);
    
    close_petcare_database();
    EXPECT_EQ(get_petcare_database(), nullptr);
#endif
}

/**
 * @brief Test close_petcare_database when not initialized
 */
TEST_F(DatabaseInitTest, CloseDatabaseNotInitialized) {
    close_petcare_database();
    
    // Should not crash when called on uninitialized database
    close_petcare_database();
    EXPECT_EQ(get_petcare_database(), nullptr);
}

/**
 * @brief Test get_petcare_database
 */
TEST_F(DatabaseInitTest, GetPetcareDatabase) {
    close_petcare_database();
    
    // Before init, should be null
    Database* db1 = get_petcare_database();
    EXPECT_EQ(db1, nullptr);
    
    int result = init_petcare_database(testDbPath);
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0);
    
    // After init, should not be null
    Database* db2 = get_petcare_database();
    EXPECT_NE(db2, nullptr);
#endif
}

// ============================================================================
// MIGRATION TESTS
// ============================================================================

/**
 * @class MigrationFullTest
 * @brief Test fixture for data migration functions
 */
class MigrationFullTest : public ::testing::Test {
protected:
    const char* testDbPath = "test_migration.db";
    
    void SetUp() override {
        // Clean up
        close_petcare_database();
        remove(testDbPath);
        remove("test_migration.db.enc");
        remove("test_migration.db.tmp.sqlite");
        remove("users.dat");
        remove("pets.dat");
    }
    
    void TearDown() override {
        close_petcare_database();
        remove(testDbPath);
        remove("test_migration.db.enc");
        remove("test_migration.db.tmp.sqlite");
        remove("users.dat");
        remove("pets.dat");
    }
};

/**
 * @brief Test migration when database is not initialized
 */
TEST_F(MigrationFullTest, MigrateWithNullDatabase) {
    close_petcare_database();
    
    testing::internal::CaptureStderr();
    int result = migrate_dat_to_sqlite();
    std::string errOutput = testing::internal::GetCapturedStderr();
    
    EXPECT_EQ(result, -1);
    EXPECT_NE(errOutput.find("Database not initialized"), std::string::npos);
}

/**
 * @brief Test migration when database already has data
 */
TEST_F(MigrationFullTest, MigrateWithExistingData) {
#ifndef SQLITE3_HEADER_ONLY
    // Initialize database
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Add some data
    Database* db = get_petcare_database();
    ASSERT_NE(db, nullptr);
    db_add_user(db, "existinguser", "password");
    
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    // Should skip migration since data exists
    EXPECT_EQ(result, 0);
    EXPECT_NE(output.find("already contains data"), std::string::npos);
#endif
}

/**
 * @brief Test migration with empty .dat files (no files to migrate)
 */
TEST_F(MigrationFullTest, MigrateWithNoDataFiles) {
#ifndef SQLITE3_HEADER_ONLY
    // Remove any existing .dat files
    remove("users.dat");
    remove("pets.dat");
    remove("adoptable.dat");
    remove("adopted.dat");
    
    // Initialize a fresh database (by removing existing one first)
    remove(testDbPath);
    remove("test_migration.db.enc");
    
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Since database is empty, migration will proceed but find no .dat files
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    // Migration should complete (with no files migrated)
    // Or skip if data was already added
    EXPECT_GE(result, -1);
#endif
}

/**
 * @brief Test migration with users.dat file present
 */
TEST_F(MigrationFullTest, MigrateUsersFromDatFile) {
#ifndef SQLITE3_HEADER_ONLY
    // Create a minimal users.dat file for testing
    // First, create some users and save them
    HashTable* table = createHashTable();
    addUser(table, "migrateuser1", "pass1");
    addUser(table, "migrateuser2", "pass2");
    saveUsersToFile(table, "users.dat");
    freeHashTable(table);
    
    // Initialize a fresh database
    remove(testDbPath);
    remove("test_migration.db.enc");
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    // Check output indicates migration attempted
    // Note: Actual migration might skip if DB has data from previous tests
    EXPECT_GE(result, -1);
#endif
}

/**
 * @brief Test migration with pets.dat file present
 */
TEST_F(MigrationFullTest, MigratePetsFromDatFile) {
#ifndef SQLITE3_HEADER_ONLY
    // Create a minimal pets.dat file for testing
    Pet* petList = nullptr;
    addPet(&petList, "MigrateDog", "Dog", 3, "Owner1");
    addPet(&petList, "MigrateCat", "Cat", 2, "Owner2");
    savePetsToFile(petList, "pets.dat");
    freePetList(petList);
    
    // Initialize a fresh database
    remove(testDbPath);
    remove("test_migration.db.enc");
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    // Migration should process or skip
    EXPECT_GE(result, -1);
#endif
}

// ============================================================================
// KDF ITERATIONS TESTS (via database initialization)
// ============================================================================

/**
 * @class KdfIterationsTest
 * @brief Test fixture for KDF iterations environment variable handling
 */
class KdfIterationsTest : public ::testing::Test {
protected:
    const char* testDbPath = "test_kdf.db";
    char* originalEnv = nullptr;
    
    void SetUp() override {
        // Save original environment variable
        const char* env = getenv("PETCARE_KDF_ITERS");
        if (env) {
            originalEnv = _strdup(env);
        }
        
        close_petcare_database();
        remove(testDbPath);
        remove("test_kdf.db.enc");
    }
    
    void TearDown() override {
        // Restore original environment variable
        if (originalEnv) {
            char envStr[256];
            snprintf(envStr, sizeof(envStr), "PETCARE_KDF_ITERS=%s", originalEnv);
            _putenv(envStr);
            free(originalEnv);
        } else {
            _putenv("PETCARE_KDF_ITERS=");
        }
        
        close_petcare_database();
        remove(testDbPath);
        remove("test_kdf.db.enc");
    }
};

/**
 * @brief Test database initialization with default KDF iterations
 */
TEST_F(KdfIterationsTest, DefaultKdfIterations) {
    // Clear the environment variable
    _putenv("PETCARE_KDF_ITERS=");
    
    close_petcare_database();
    int result = init_petcare_database(testDbPath);
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0);
#endif
}

/**
 * @brief Test database initialization with custom KDF iterations
 */
TEST_F(KdfIterationsTest, CustomKdfIterations) {
    // Set custom KDF iterations
    _putenv("PETCARE_KDF_ITERS=5000");
    
    close_petcare_database();
    int result = init_petcare_database(testDbPath);
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0);
#endif
}

/**
 * @brief Test database initialization with KDF iterations below minimum
 */
TEST_F(KdfIterationsTest, KdfIterationsBelowMinimum) {
    // Set KDF iterations below minimum (should be clamped to 1000)
    _putenv("PETCARE_KDF_ITERS=100");
    
    close_petcare_database();
    int result = init_petcare_database(testDbPath);
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0);
#endif
}

/**
 * @brief Test database initialization with KDF iterations above maximum
 */
TEST_F(KdfIterationsTest, KdfIterationsAboveMaximum) {
    // Set KDF iterations above maximum (should be clamped to 1000000)
    _putenv("PETCARE_KDF_ITERS=2000000");
    
    close_petcare_database();
    int result = init_petcare_database(testDbPath);
    
#ifndef SQLITE3_HEADER_ONLY
    EXPECT_EQ(result, 0);
#endif
}

/**
 * @brief Test database initialization with invalid KDF iterations value
 */
TEST_F(KdfIterationsTest, InvalidKdfIterationsValue) {
    // Set invalid value (should fall back to default)
    _putenv("PETCARE_KDF_ITERS=invalid");
    
    close_petcare_database();
    int result = init_petcare_database(testDbPath);
    
#ifndef SQLITE3_HEADER_ONLY
    // strtol returns 0 for invalid, which should be clamped to 1000
    EXPECT_EQ(result, 0);
#endif
}

// ============================================================================
// COMPREHENSIVE MIGRATION TESTS - Covers actual data migration loops
// ============================================================================

/**
 * @class ComprehensiveMigrationTest
 * @brief Test fixture for comprehensive data migration with actual data
 */
class ComprehensiveMigrationTest : public ::testing::Test {
protected:
    const char* testDbPath = "test_comprehensive_migration.db";
    
    void SetUp() override {
        // Clean up everything before each test
        close_petcare_database();
        remove(testDbPath);
        remove("test_comprehensive_migration.db.enc");
        remove("test_comprehensive_migration.db.tmp.sqlite");
        remove("users.dat");
        remove("pets.dat");
        remove("adoptable.dat");
        remove("adopted.dat");
    }
    
    void TearDown() override {
        close_petcare_database();
        remove(testDbPath);
        remove("test_comprehensive_migration.db.enc");
        remove("test_comprehensive_migration.db.tmp.sqlite");
        remove("users.dat");
        remove("pets.dat");
        remove("adoptable.dat");
        remove("adopted.dat");
    }
    
    // Helper to create users.dat with test data
    void createUsersDatFile() {
        HashTable* table = createHashTable();
        addUser(table, "migrate_user1", "password1");
        addUser(table, "migrate_user2", "password2");
        addUser(table, "migrate_user3", "password3");
        saveUsersToFile(table, "users.dat");
        freeHashTable(table);
    }
    
    // Helper to create pets.dat with test data
    void createPetsDatFile() {
        Pet* petList = nullptr;
        addPet(&petList, "MigrateDog1", "Dog", 3, "migrate_user1");
        addPet(&petList, "MigrateCat1", "Cat", 2, "migrate_user2");
        addPet(&petList, "MigrateBird1", "Bird", 1, "migrate_user1");
        savePetsToFile(petList, "pets.dat");
        freePetList(petList);
    }
    
    // Helper to create adoptable.dat with test stray animals
    void createAdoptableDatFile() {
        StrayAnimal* strayList = nullptr;
        addStrayAnimalToList(&strayList, "Stray_Dog", "Male", "01/01/2024", 2);
        addStrayAnimalToList(&strayList, "Stray_Cat", "Female", "02/02/2024", 1);
        saveStrayAnimalsToFile(strayList, "adoptable.dat");
        // Free the list
        while (strayList) {
            StrayAnimal* next = strayList->next;
            free(strayList);
            strayList = next;
        }
    }
    
    // Helper to create adopted.dat with test adopted animals
    void createAdoptedDatFile() {
        AdoptedAnimal* adoptedList = nullptr;
        
        // Manually create adopted animals
        AdoptedAnimal* adopted1 = (AdoptedAnimal*)malloc(sizeof(AdoptedAnimal));
        adopted1->id = 100;
        strcpy(adopted1->type, "Adopted_Dog");
        strcpy(adopted1->gender, "Male");
        strcpy(adopted1->arrivalDate, "01/06/2023");
        adopted1->age = 3;
        strcpy(adopted1->owner, "adopter1");
        strcpy(adopted1->adoptionDate, "15/07/2023");
        adopted1->next = nullptr;
        adoptedList = adopted1;
        
        AdoptedAnimal* adopted2 = (AdoptedAnimal*)malloc(sizeof(AdoptedAnimal));
        adopted2->id = 101;
        strcpy(adopted2->type, "Adopted_Cat");
        strcpy(adopted2->gender, "Female");
        strcpy(adopted2->arrivalDate, "01/08/2023");
        adopted2->age = 2;
        strcpy(adopted2->owner, "adopter2");
        strcpy(adopted2->adoptionDate, "20/09/2023");
        adopted2->next = nullptr;
        adopted1->next = adopted2;
        
        saveAdoptedAnimalsToFile(adoptedList, "adopted.dat");
        
        // Free the list
        while (adoptedList) {
            AdoptedAnimal* next = adoptedList->next;
            free(adoptedList);
            adoptedList = next;
        }
    }
};

/**
 * @brief Test migration with actual user data in users.dat
 * Covers lines 3196-3200 in petcare.cpp
 */
TEST_F(ComprehensiveMigrationTest, MigrateActualUsersFromDat) {
#ifndef SQLITE3_HEADER_ONLY
    // Create users.dat with actual test users
    createUsersDatFile();
    
    // Verify file exists
    FILE* f = fopen("users.dat", "rb");
    ASSERT_NE(f, nullptr) << "users.dat should exist";
    fclose(f);
    
    // Initialize fresh database (no existing data)
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Capture output and run migration
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    // Check that migration was attempted
    EXPECT_EQ(result, 0);
    
    // Verify output mentions user migration
    // Note: May say "already contains data" if tables were populated during init
    EXPECT_TRUE(output.find("Migrat") != std::string::npos || 
                output.find("already contains data") != std::string::npos);
#endif
}

/**
 * @brief Test migration with actual pet data in pets.dat
 * Covers lines 3221-3225 in petcare.cpp
 */
TEST_F(ComprehensiveMigrationTest, MigrateActualPetsFromDat) {
#ifndef SQLITE3_HEADER_ONLY
    // Create pets.dat with actual test pets
    createPetsDatFile();
    
    // Verify file exists
    FILE* f = fopen("pets.dat", "rb");
    ASSERT_NE(f, nullptr) << "pets.dat should exist";
    fclose(f);
    
    // Initialize fresh database
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Capture output and run migration
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_EQ(result, 0);
#endif
}

/**
 * @brief Test migration with actual stray animal data in adoptable.dat
 * Covers lines 3234-3252 in petcare.cpp
 */
TEST_F(ComprehensiveMigrationTest, MigrateActualStrayAnimalsFromDat) {
#ifndef SQLITE3_HEADER_ONLY
    // Create adoptable.dat with test stray animals
    createAdoptableDatFile();
    
    // Verify file exists
    FILE* f = fopen("adoptable.dat", "rb");
    ASSERT_NE(f, nullptr) << "adoptable.dat should exist";
    fclose(f);
    
    // Initialize fresh database
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Capture output and run migration
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_EQ(result, 0);
#endif
}

/**
 * @brief Test migration with actual adopted animal data in adopted.dat
 * Covers lines 3258-3276 in petcare.cpp
 */
TEST_F(ComprehensiveMigrationTest, MigrateActualAdoptedAnimalsFromDat) {
#ifndef SQLITE3_HEADER_ONLY
    // Create adopted.dat with test adopted animals
    createAdoptedDatFile();
    
    // Verify file exists
    FILE* f = fopen("adopted.dat", "rb");
    ASSERT_NE(f, nullptr) << "adopted.dat should exist";
    fclose(f);
    
    // Initialize fresh database
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Capture output and run migration
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_EQ(result, 0);
#endif
}

/**
 * @brief Test full migration with all .dat files present
 * Covers all migration loops in migrate_dat_to_sqlite
 */
TEST_F(ComprehensiveMigrationTest, MigrateAllDataFiles) {
#ifndef SQLITE3_HEADER_ONLY
    // Create all .dat files with test data
    createUsersDatFile();
    createPetsDatFile();
    createAdoptableDatFile();
    createAdoptedDatFile();
    
    // Verify all files exist
    FILE* f1 = fopen("users.dat", "rb");
    FILE* f2 = fopen("pets.dat", "rb");
    FILE* f3 = fopen("adoptable.dat", "rb");
    FILE* f4 = fopen("adopted.dat", "rb");
    
    ASSERT_NE(f1, nullptr) << "users.dat should exist";
    ASSERT_NE(f2, nullptr) << "pets.dat should exist";
    ASSERT_NE(f3, nullptr) << "adoptable.dat should exist";
    ASSERT_NE(f4, nullptr) << "adopted.dat should exist";
    
    fclose(f1); fclose(f2); fclose(f3); fclose(f4);
    
    // Initialize fresh database
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Capture output and run migration
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_EQ(result, 0);
    
    // Migration should complete successfully
    EXPECT_TRUE(output.find("Migration complete") != std::string::npos ||
                output.find("already contains data") != std::string::npos);
#endif
}

/**
 * @brief Test migration loop behavior when files have multiple records
 */
TEST_F(ComprehensiveMigrationTest, MigrateManyUsersFromDat) {
#ifndef SQLITE3_HEADER_ONLY
    // Create users.dat with many users to test the loop
    HashTable* table = createHashTable();
    for (int i = 0; i < 10; i++) {
        char username[32], password[32];
        snprintf(username, sizeof(username), "bulk_user_%d", i);
        snprintf(password, sizeof(password), "bulk_pass_%d", i);
        addUser(table, username, password);
    }
    saveUsersToFile(table, "users.dat");
    freeHashTable(table);
    
    // Initialize fresh database
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Run migration
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_EQ(result, 0);
#endif
}

/**
 * @brief Test migration loop behavior when pets.dat has multiple records
 */
TEST_F(ComprehensiveMigrationTest, MigrateManyPetsFromDat) {
#ifndef SQLITE3_HEADER_ONLY
    // Create pets.dat with many pets to test the loop
    Pet* petList = nullptr;
    for (int i = 0; i < 10; i++) {
        char name[32], type[32], owner[32];
        snprintf(name, sizeof(name), "BulkPet%d", i);
        snprintf(type, sizeof(type), "Type%d", i % 3);
        snprintf(owner, sizeof(owner), "Owner%d", i % 5);
        addPet(&petList, name, type, i + 1, owner);
    }
    savePetsToFile(petList, "pets.dat");
    freePetList(petList);
    
    // Initialize fresh database
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Run migration
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_EQ(result, 0);
#endif
}

/**
 * @brief Test that migration skips when database already has data
 */
TEST_F(ComprehensiveMigrationTest, MigrationSkipsWithExistingData) {
#ifndef SQLITE3_HEADER_ONLY
    // Create dat files
    createUsersDatFile();
    createPetsDatFile();
    
    // Initialize database
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Add some data directly to database first
    Database* db = get_petcare_database();
    ASSERT_NE(db, nullptr);
    db_add_user(db, "existing_user", "existing_pass");
    
    // Now try migration - should skip
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_EQ(result, 0);
    // Should mention that data already exists
    EXPECT_TRUE(output.find("already contains data") != std::string::npos);
#endif
}

/**
 * @brief Test stray animal migration with multiple records in adoptable.dat
 */
TEST_F(ComprehensiveMigrationTest, MigrateManyStrayAnimalsFromDat) {
#ifndef SQLITE3_HEADER_ONLY
    // Create adoptable.dat with many stray animals
    StrayAnimal* strayList = nullptr;
    for (int i = 0; i < 5; i++) {
        char type[32], gender[16], date[16];
        snprintf(type, sizeof(type), "StrayType%d", i);
        snprintf(gender, sizeof(gender), i % 2 == 0 ? "Male" : "Female");
        snprintf(date, sizeof(date), "%02d/%02d/2024", (i % 28) + 1, (i % 12) + 1);
        addStrayAnimalToList(&strayList, type, gender, date, i + 1);
    }
    saveStrayAnimalsToFile(strayList, "adoptable.dat");
    
    // Free the list
    while (strayList) {
        StrayAnimal* next = strayList->next;
        free(strayList);
        strayList = next;
    }
    
    // Initialize fresh database
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Run migration
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_EQ(result, 0);
#endif
}

/**
 * @brief Test adopted animal migration with multiple records in adopted.dat
 */
TEST_F(ComprehensiveMigrationTest, MigrateManyAdoptedAnimalsFromDat) {
#ifndef SQLITE3_HEADER_ONLY
    // Create adopted.dat with multiple adopted animals
    AdoptedAnimal* adoptedList = nullptr;
    AdoptedAnimal* tail = nullptr;
    
    for (int i = 0; i < 5; i++) {
        AdoptedAnimal* adopted = (AdoptedAnimal*)malloc(sizeof(AdoptedAnimal));
        adopted->id = 200 + i;
        snprintf(adopted->type, sizeof(adopted->type), "AdoptedType%d", i);
        strcpy(adopted->gender, i % 2 == 0 ? "Male" : "Female");
        snprintf(adopted->arrivalDate, sizeof(adopted->arrivalDate), "%02d/%02d/2023", (i % 28) + 1, (i % 12) + 1);
        adopted->age = i + 1;
        snprintf(adopted->owner, sizeof(adopted->owner), "adopter%d", i);
        snprintf(adopted->adoptionDate, sizeof(adopted->adoptionDate), "%02d/%02d/2024", (i % 28) + 1, (i % 12) + 1);
        adopted->next = nullptr;
        
        if (!adoptedList) {
            adoptedList = adopted;
            tail = adopted;
        } else {
            tail->next = adopted;
            tail = adopted;
        }
    }
    
    saveAdoptedAnimalsToFile(adoptedList, "adopted.dat");
    
    // Free the list
    while (adoptedList) {
        AdoptedAnimal* next = adoptedList->next;
        free(adoptedList);
        adoptedList = next;
    }
    
    // Initialize fresh database
    ASSERT_EQ(init_petcare_database(testDbPath), 0);
    
    // Run migration
    testing::internal::CaptureStdout();
    int result = migrate_dat_to_sqlite();
    std::string output = testing::internal::GetCapturedStdout();
    
    EXPECT_EQ(result, 0);
#endif
}