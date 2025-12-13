/*
 * Copyright (C) 2024 Hideki Ikeda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.czeal.rfc3986;


import static org.czeal.rfc3986.Utils.fromHexDigit;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * An abstract class for processing percent-encoded strings.
 *
 * @author Hideki Ikeda
 */
abstract class PercentEncodedStringProcessor
{
    /**
     * Information about percent-encoded values.
     */
    protected static class Info
    {
        private StringBuffer          sb = new StringBuffer();
        private ByteArrayOutputStream bs = new ByteArrayOutputStream();


        /**
         * Saves the given information.
         *
         * @param percentEncodedValue
         *         The percent-encoded value.
         *
         * @param byteForPercentEncodedValue
         *         The byte represented by the percent-encoded value.
         */
        void add(String percentEncodedValue, byte byteForPercentEncodedValue)
        {
            sb.append(percentEncodedValue);
            bs.write(byteForPercentEncodedValue);
        }


        /**
         * Returns the sequence of the percent-encoded values.
         *
         * @return
         *         The sequence of the percent-encoded values.
         */
        String getString()
        {
            return sb.toString();
        }


        /**
         * Returns the bytes represented by the percent-encoded values.
         *
         * @return
         *         The bytes represented by the percent-encoded values.
         */
        byte[] getByteArray()
        {
            return bs.toByteArray();
        }


        /**
         * Resets the internal information.
         */
        void reset()
        {
            sb.setLength(0);
            bs.reset();
        }
    }


    /**
     * Processes an input string that could contain percent-encoded values and
     * outputs a string if necessary.
     *
     * @param input
     *         The input string.
     *
     * @param charset
     *         The charset used in the input string.
     *
     * @param outputBuilder
     *         The output string builder . This property is expected to be populated
     *         in either/both {@link PercentEncodedStringProcessor#onDecoded(Charset, StringBuilder, CharBuffer)
     *         onDecoded(Charset, StringBuilder, CharBuffer)} method or/and {@link
     *         PercentEncodedStringProcessor#onNonPercent(String, StringBuilder, char, int)
     *         onNonPercent(String, StringBuilder, char, int)} method in subclasses.
     *
     * @return
     *         A string built by {@code outputBuilder} if {@code outputBuilder}
     *         is specified; otherwise, {@code null}.
     */
    protected String process(String input, Charset charset, StringBuilder outputBuilder)
    {
        // The current index.
        int currentIndex = 0;

        // The last index.
        int lastIndex = input.length() - 1;

        // The stream to store bytes represented by percent-encoded values.
        Info info = new Info();

        while (currentIndex <= lastIndex)
        {
            // The character at the current index.
            char c = input.charAt(currentIndex);

            if (c == '%')
            {
                // If the character is "%", which indicates a percent-encoded
                // value, process the percent-encoded value.
                onPercent(input, charset, outputBuilder, currentIndex, lastIndex, info);
                currentIndex += 3;
            }
            else
            {
                // If the character is not "%", process the character.
                onNonPercent(input, outputBuilder, c, currentIndex);
                currentIndex++;
            }
        }

        // Build the output string if the output builder is specified.
        return outputBuilder == null ? null : outputBuilder.toString();
    }


    private void onPercent(
        String input, Charset charset, StringBuilder outputBuilder, int currentIndex,
        int lastIndex, Info info)
    {
        // Ensure there are characters at indexes "currentIndex + 1" and
        // "currentIndex + 2" in the input.
        if (currentIndex + 2 > lastIndex)
        {
            throw onMalformedPercentEncodedValue(input, currentIndex);
        }

        // Extract the target percent-encoded value "%XX" from the input string.
        String percentEncodedValue = input.substring(currentIndex, currentIndex + 3);

        // Convert the higher and lower hex digits of the percent-encoded value
        // to a byte.
        byte b = toByte(input, currentIndex + 1, currentIndex + 2);

        // Save the percent-encoded value and the bytes.
        info.add(percentEncodedValue, b);

        // If the next index (currentIndex + 3) exceeds the last index  or the
        // character at the next index is not '%'.
        int nextIndex = currentIndex + 3;
        if (nextIndex > lastIndex || input.charAt(nextIndex) != '%')
        {
            // Decode the percent-encoded values.
            decode(input, charset, outputBuilder, info);

            // Reset the information about the percent-encoded values.
            info.reset();
        }
    }


    private byte toByte(String input, int higherHexDigitIndex, int lowerHexDigitIndex)
    {
        // The higher hex digit.
        char higherHexDigit = input.charAt(higherHexDigitIndex);

        // Read the higher hex digit in the percent-encoded value and convert it
        // to an int value.
        int intOfHigherHexDigit = toIntOfHexDigit(
            input, higherHexDigitIndex, higherHexDigit);

        // The lower hex digit.
        char lowerHexDigit = input.charAt(lowerHexDigitIndex);

        // Read the lower hex digit in the percent-encoded value and convert it
        // to an int value.
        int intOfLowerHexDigit = toIntOfHexDigit(
            input, lowerHexDigitIndex, lowerHexDigit);

        // Calculate a byte represented by the percent-encoded value.
        return (byte)( (intOfHigherHexDigit << 4) + intOfLowerHexDigit );
    }


    private int toIntOfHexDigit(String input, int index, char hexDigit)
    {
        // Convert the hex digit to an int value.
        int intOfHexDigit = fromHexDigit(hexDigit);

        // Ensure the hex digit is valid.
        if (intOfHexDigit == -1)
        {
            throw onInvalidHexDigit(input, hexDigit, index);
        }

        // Return the int value.
        return intOfHexDigit;
    }


    private void decode(
        String input, Charset charset, StringBuilder outputBuilder, Info info)
    {
        // The buffer to store decoded results.
        CharBuffer docodedCharBuffer;

        try
        {
            // Decode the bytes stored in the byte stream.
            docodedCharBuffer = charset.newDecoder()
                .decode( ByteBuffer.wrap(info.getByteArray()) );
        }
        catch (CharacterCodingException e)
        {
            // Failed to decode bytes represented by a sequence of percent-encoded
            // values.
            throw onDecodeFailed(input, info);
        }

        // Process when the percent-encoded values have been decoded.
        onDecoded(charset, outputBuilder, docodedCharBuffer);
    }


    /**
     * Invoked when a malformed percent-encoded value is found in the input.
     *
     * @param input
     *         The input value.
     *
     * @param index
     *         The index of the malformed percent-encoded value in the input.
     *
     * @return
     *         An {@code IllegalArgumentException} to be thrown.
     */
    protected abstract IllegalArgumentException onMalformedPercentEncodedValue(
        String input, int index);


    /**
     * Invoked when an invalid hex digit is found in the input.
     *
     * @param input
     *         The input value.
     *
     * @param hexDigit
     *         The invalid hex digit.
     *
     * @param index
     *         The index of the invalid hex digit in the input.
     *
     * @return
     *         An {@code IllegalArgumentException} to be thrown.
     */
    protected abstract IllegalArgumentException onInvalidHexDigit(
        String input, char hexDigit, int index);


    /**
     * Invoked when failed to decoded percent-encoded values contained in the input.
     *
     * @param input
     *         The input value.
     *
     * @param info
     *         Information about the percent-encoded values.
     *
     * @return
     *         An {@code IllegalArgumentException} to be thrown.
     */
    protected abstract IllegalArgumentException onDecodeFailed(String input, Info info);


    /**
     * Invoked when percent-encoded values contained in the input have been
     * successfully decoded.
     *
     * @param charset
     *         The charset.
     *
     * @param outputBuilder
     *         The output builder.
     *
     * @param buffer
     *         The char buffer containing decoded characters.
     */
    protected abstract void onDecoded(
        Charset charset, StringBuilder outputBuilder, CharBuffer buffer);


    /**
     * Invoked when a non-percent value is found in the input.
     *
     * @param input
     *         The input value.
     *
     * @param outputBuilder
     *         The output builder.
     *
     * @param c
     *         The non-percent character.
     *
     * @param index
     *         The index of the non-percent character in the input.
     */
    protected abstract void onNonPercent(
        String input, StringBuilder outputBuilder, char c, int index);
}
