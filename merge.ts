export function merge(collection_1: number[], collection_2: number[]): Array<number> {

    // Merged number collection
    const merged: number[] = [];
    // Pointers for both input collection
    let index_1 = 0;
    let index_2 = 0;

    // Choose lesser number from the pointer position, then move the pointer of selected collection
    while (index_1 < collection_1.length && index_2 < collection_2.length) {
        if (collection_1[index_1] < collection_2[index_2]) {
            merged.push(collection_1[index_1]);
            index_1++;
        } else {
            merged.push(collection_2[index_2]);
            index_2++;
        }
    }

    // Push the remaining numbers when the other collection is exhausted
    while (index_1 < collection_1.length) {
        merged.push(collection_1[index_1]);
        index_1++;
    }
    while (index_2 < collection_2.length) {
        merged.push(collection_2[index_2]);
        index_2++;
    }

    return merged;
}