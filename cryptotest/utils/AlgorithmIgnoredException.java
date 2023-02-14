/*
 * The MIT License
 *
 * Copyright 2023 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package cryptotest.utils;

/**
 *
 * This exception indicates that algorithm testing was skipped
 * but is not treated as failure.
 * Possible use cases:
 * - testing of algorithm does not make sence (or does not fully work)
 *   in given configuration (e.g. failure is NOT A BUG)
 * - testing of given algorithm is not yet implemented..
 *   (e.g. difficult to test)
 */
public class AlgorithmIgnoredException extends RuntimeException {

    public AlgorithmIgnoredException() {
    }

    public AlgorithmIgnoredException(String s) {
        super(s);
    }

}
