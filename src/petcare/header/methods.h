/**
 * @file methods.h
 */
#ifndef METHODS_H
#define METHODS_H

/**
 * @brief Maximum tree height for Huffman coding
 */
#define MAX_TREE_HT 100

 /**
  * @brief Represents a node in the Huffman Min-Heap.
  */
typedef struct MinHeapNode {
    char data;                     /**< Character data */
    unsigned freq;                 /**< Frequency of the character */
    struct MinHeapNode* left;      /**< Pointer to left child */
    struct MinHeapNode* right;     /**< Pointer to right child */
} MinHeapNode;

/**
 * @brief Represents a Min-Heap for Huffman coding.
 */
typedef struct MinHeap {
    unsigned size;                 /**< Current size of the heap */
    unsigned capacity;             /**< Maximum capacity of the heap */
    MinHeapNode** array;           /**< Array of node pointers */
} MinHeap;

/**
 * @brief Creates a new Huffman tree node.
 * @param data Character data.
 * @param freq Frequency of the character.
 * @return Pointer to the newly created MinHeapNode.
 */
MinHeapNode* newNode(char data, unsigned freq);

/**
 * @brief Creates a Min-Heap with a given capacity.
 * @param capacity Maximum capacity of the Min-Heap.
 * @return Pointer to the newly created MinHeap.
 */
MinHeap* createMinHeap(unsigned capacity);

/**
 * @brief Swaps two MinHeapNode pointers.
 * @param a Pointer to the first node.
 * @param b Pointer to the second node.
 */
void swapMinHeapNode(MinHeapNode** a, MinHeapNode** b);

/**
 * @brief Maintains the min-heap property at a given index.
 * @param minHeap Pointer to the MinHeap.
 * @param idx Index to enforce min-heap property.
 */
void minHeapify(MinHeap* minHeap, int idx);

/**
 * @brief Extracts the minimum value node from the Min-Heap.
 * @param minHeap Pointer to the MinHeap.
 * @return Pointer to the extracted MinHeapNode (smallest frequency).
 */
MinHeapNode* extractMin(MinHeap* minHeap);

/**
 * @brief Inserts a new node into the Min-Heap.
 * @param minHeap Pointer to the MinHeap.
 * @param minHeapNode Node to be inserted.
 */
void insertMinHeap(MinHeap* minHeap, MinHeapNode* minHeapNode);

/**
 * @brief Builds a Min-Heap from arrays of characters and frequencies.
 * @param data Array of characters.
 * @param freq Array of frequencies corresponding to the characters.
 * @param size Number of unique characters.
 * @return Pointer to the constructed MinHeap.
 */
MinHeap* buildMinHeap(char data[], int freq[], int size);

/**
 * @brief Builds a Huffman tree from given data and frequency arrays.
 * @param data Array of characters.
 * @param freq Array of frequencies.
 * @param size Number of unique characters.
 * @return Pointer to the root of the Huffman tree.
 */
MinHeapNode* buildHuffmanTree(char data[], int freq[], int size);

/**
 * @brief Recursively computes and prints Huffman codes for each character.
 * @param root Pointer to the root of the Huffman tree.
 * @param arr Array used to store the current code (as bits 0 or 1).
 * @param top Current index in the code array.
 * @param codes 2D array to store the resulting codes for each character.
 */
void printCodes(MinHeapNode* root, int arr[], int top, char codes[256][MAX_TREE_HT]);

/**
 * @brief Generates Huffman codes for all characters in the given data array.
 * @param data Array of characters.
 * @param freq Array of frequencies.
 * @param size Number of unique characters.
 * @param codes 2D array to store the resulting codes for each character.
 */
void HuffmanCodes(char data[], int freq[], int size, char codes[256][MAX_TREE_HT]);

/**
 * @brief Compresses the input string using the provided Huffman codes.
 * @param input Input string to compress.
 * @param codes 2D array of Huffman codes for each character.
 * @param output Buffer to store the compressed string (bit sequence).
 */
void compress(char* input, char codes[256][MAX_TREE_HT], char* output);

/**
 * @brief Decompresses a bit-sequence string using the given Huffman tree.
 * @param root Pointer to the root of the Huffman tree.
 * @param compressed The compressed bit-sequence.
 * @param output Buffer to store the decompressed string.
 */
void decompress(MinHeapNode* root, char* compressed, char* output);

#endif
