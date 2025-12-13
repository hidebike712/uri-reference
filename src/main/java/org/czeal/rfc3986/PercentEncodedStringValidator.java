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


import static org.czeal.rfc3986.Utils.newIAE;
import java.nio.CharBuffer;
import java.nio.charset.Charset;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * An abstract class for validating percent-encoded strings.
 *
 * @author Hideki Ikeda
 */
abstract class PercentEncodedStringValidator extends PercentEncodedStringProcessor
{
    protected final String name;


    protected PercentEncodedStringValidator(String name)
    {
        this.name = name;
    }


    @Override
    protected void onDecoded(
        Charset charset, StringBuilder outputBuilder, CharBuffer buffer)
    {
        // Do nothing.
    }


    @Override
    protected void onNonPercent(
        String input, StringBuilder outputBuilder, char c, int index)
    {
        if (!isValidOnNonPercent(c))
        {
            throw newIAE(
                "The %s value \"%s\" has an invalid character \"%s\" at the index %d.",
                name, input, c, index);
        }
    }


    @Override
    protected IllegalArgumentException onMalformedPercentEncodedValue(
        String input, int index)
    {
        throw newIAE(
            "The percent symbol \"%%\" at the index %d in the %s value \"%s\" is " +
            "not followed by two characters.", index, name, input);
    }


    @Override
    protected IllegalArgumentException onInvalidHexDigit(
        String input, char hexDigit, int index)
    {
        throw newIAE(
            "The %s value \"%s\" has an invalid hex digit \"%c\" at the index %d.",
            name, input, hexDigit, index);
    }


    @Override
    protected IllegalArgumentException onDecodeFailed(String input, Info info)
    {
        throw newIAE(
            "Failed to decode bytes represented by \"%s\" in the %s value \"%s\".",
            info.getString(), name, input);
    }


    /**
     * Checks whether or not the character is valid as a non-percent value.
     *
     * @param c The character to check.
     *
     * @return
     *         {@code true} if the character is valid as a non-percent value;
     *         otherwise, {@code false}.
     */
    protected abstract boolean isValidOnNonPercent(char c);
}
