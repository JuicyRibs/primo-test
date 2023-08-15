import { merge } from './merge';

describe('test merge function', () => {
    it('should merges two sorted arrays', () => {
        const arr1 = [1, 3, 5, 7];
        const arr2 = [2, 4, 6, 8];
        const merged = merge(arr1, arr2);
        expect(merged).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    });

    it('should handles empty arrays', () => {
        const arr1: number[] = [];
        const arr2 = [2, 4, 6, 8, 9];
        const merged = merge(arr1, arr2);
        expect(merged).toEqual([2, 4, 6, 8, 9]);
    });

    it('should handles different size arrays', () => {
        const arr1 = [0, 1, 3, 5, 9];
        const arr2 = [2, 4, 6, 8];
        const merged = merge(arr1, arr2);
        expect(merged).toEqual([0, 1, 2, 3, 4, 5, 6, 8, 9]);
    });
});
