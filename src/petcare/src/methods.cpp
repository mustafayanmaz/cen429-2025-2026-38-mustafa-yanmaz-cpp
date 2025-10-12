/**
 * @file methods.cpp
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "methods.h"

/**
 * @brief Creates a new Huffman tree node.
 * @param data The character stored in the node.
 * @param freq The frequency of the character.
 * @return Pointer to the newly created node (MinHeapNode*).
 */
MinHeapNode* newNode(char data, unsigned freq) {
    MinHeapNode* temp = (MinHeapNode*)malloc(sizeof(MinHeapNode));
    temp->left = temp->right = NULL;
    temp->data = data;
    temp->freq = freq;
    return temp;
}

/**
 * @brief Creates a Min-Heap for Huffman coding.
 * @param capacity The maximum capacity of the Min-Heap.
 * @return Pointer to the newly created MinHeap structure.
 */
MinHeap* createMinHeap(unsigned capacity) {
    MinHeap* minHeap = (MinHeap*)malloc(sizeof(MinHeap));
    minHeap->size = 0;
    minHeap->capacity = capacity;
    minHeap->array = (MinHeapNode**)malloc(minHeap->capacity * sizeof(MinHeapNode*));
    return minHeap;
}

/**
 * @brief Swaps two MinHeapNode pointers.
 * @param a Pointer to the first node.
 * @param b Pointer to the second node.
 */
void swapMinHeapNode(MinHeapNode** a, MinHeapNode** b) {
    MinHeapNode* t = *a;
    *a = *b;
    *b = t;
}

/**
 * @brief Ensures the min-heap property for the node at the given index.
 * @param minHeap Pointer to the MinHeap.
 * @param idx Index at which to enforce the min-heap property.
 */
void minHeapify(MinHeap* minHeap, int idx) {
    int smallest = idx;
    int left = 2 * idx + 1;
    int right = 2 * idx + 2;

    if ((unsigned)left < minHeap->size && minHeap->array[left]->freq < minHeap->array[smallest]->freq)
        smallest = left;

    if ((unsigned)right < minHeap->size && minHeap->array[right]->freq < minHeap->array[smallest]->freq)
        smallest = right;

    if (smallest != idx) {
        swapMinHeapNode(&minHeap->array[smallest], &minHeap->array[idx]);
        minHeapify(minHeap, smallest);
    }
}

/**
 * @brief Extracts the node with the smallest frequency from the Min-Heap.
 * @param minHeap Pointer to the MinHeap.
 * @return Pointer to the extracted node.
 */
MinHeapNode* extractMin(MinHeap* minHeap) {
    MinHeapNode* temp = minHeap->array[0];
    minHeap->array[0] = minHeap->array[minHeap->size - 1];
    --minHeap->size;
    minHeapify(minHeap, 0);
    return temp;
}

/**
 * @brief Inserts a node into the Min-Heap.
 * @param minHeap Pointer to the MinHeap.
 * @param minHeapNode Pointer to the node to insert.
 */
void insertMinHeap(MinHeap* minHeap, MinHeapNode* minHeapNode) {
    ++minHeap->size;
    int i = minHeap->size - 1;

    while (i && minHeapNode->freq < minHeap->array[(i - 1) / 2]->freq) {
        minHeap->array[i] = minHeap->array[(i - 1) / 2];
        i = (i - 1) / 2;
    }
    minHeap->array[i] = minHeapNode;
}

/**
 * @brief Builds a Min-Heap from the given arrays of data and frequencies.
 * @param data Array of characters.
 * @param freq Array of frequencies corresponding to each character.
 * @param size Size of the data/freq arrays.
 * @return Pointer to the created MinHeap.
 */
MinHeap* buildMinHeap(char data[], int freq[], int size) {
    MinHeap* minHeap = createMinHeap(size);

    for (int i = 0; i < size; ++i) {
        minHeap->array[i] = newNode(data[i], freq[i]);
    }

    minHeap->size = size;

    for (int i = (minHeap->size - 2) / 2; i >= 0; --i) {
        minHeapify(minHeap, i);
    }

    return minHeap;
}

/**
 * @brief Builds the Huffman tree from arrays of data and frequencies.
 * @param data Array of characters.
 * @param freq Array of frequencies corresponding to each character.
 * @param size The number of unique characters in data.
 * @return Pointer to the root of the Huffman tree.
 */
MinHeapNode* buildHuffmanTree(char data[], int freq[], int size) {
    MinHeapNode *left, *right, *top;
    MinHeap* minHeap = buildMinHeap(data, freq, size);

    while (minHeap->size != 1) {
        left = extractMin(minHeap);
        right = extractMin(minHeap);
        top = newNode('$', left->freq + right->freq);
        top->left = left;
        top->right = right;
        insertMinHeap(minHeap, top);
    }
    return extractMin(minHeap);
}

/**
 * @brief Helper function to print Huffman codes for each character.
 *        Also stores the generated codes in the 'codes' array.
 * @param root Pointer to the root of the Huffman tree.
 * @param arr An integer array used during code construction.
 * @param top Current index in arr.
 * @param codes A 2D array to store Huffman codes for each character (indexed by char).
 */
void printCodes(MinHeapNode* root, int arr[], int top, char codes[256][MAX_TREE_HT]) {
    if (root->left) {
        arr[top] = 0;
        printCodes(root->left, arr, top + 1, codes);
    }
    if (root->right) {
        arr[top] = 1;
        printCodes(root->right, arr, top + 1, codes);
    }
    if (!(root->left) && !(root->right)) {
        codes[(int)root->data][0] = '\0';
        printf("%c: ", root->data);
        for (int i = 0; i < top; ++i) {
            printf("%d", arr[i]);
            codes[(int)root->data][i] = '0' + arr[i];
            codes[(int)root->data][i + 1] = '\0';
        }
        printf("\n");
    }
}

/**
 * @brief Generates Huffman codes for the given data and frequencies.
 * @param data Array of characters.
 * @param freq Array of frequencies corresponding to each character.
 * @param size Number of unique characters in data.
 * @param codes A 2D array to store the generated Huffman codes.
 */
void HuffmanCodes(char data[], int freq[], int size, char codes[256][MAX_TREE_HT]) {
    MinHeapNode* root = buildHuffmanTree(data, freq, size);
    int arr[MAX_TREE_HT], top = 0;
    printCodes(root, arr, top, codes);
}

/**
 * @brief Compresses the input string using the provided Huffman codes.
 * @param input The input string to be compressed.
 * @param codes A 2D array of Huffman codes (indexed by character).
 * @param output The output buffer for the compressed string.
 */
void compress(char* input, char codes[256][MAX_TREE_HT], char* output) {
    size_t output_pos = 0;
    for (int i = 0; input[i] != '\0'; ++i) {
        const char* code = codes[(int)input[i]];
        size_t j = 0;
        // Manually copy each character from code to output
        while (code[j] != '\0') {
            output[output_pos++] = code[j++];
        }
    }
    output[output_pos] = '\0';
}

/**
 * @brief Decompresses the given Huffman-coded string into the original text.
 * @param root Pointer to the root of the Huffman tree.
 * @param compressed The compressed binary string.
 * @param output The output buffer for the decompressed string.
 */
void decompress(MinHeapNode* root, char* compressed, char* output) {
    MinHeapNode* current = root;
    int j = 0;
    for (int i = 0; compressed[i] != '\0'; ++i) {
        current = (compressed[i] == '0') ? current->left : current->right;

        if (!(current->left) && !(current->right)) {
            output[j++] = current->data;
            current = root;
        }
    }
    output[j] = '\0';
}
