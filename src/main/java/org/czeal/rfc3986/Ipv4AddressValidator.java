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


import static org.czeal.rfc3986.Utils.isDigit;
import static org.czeal.rfc3986.Utils.isInRange;
import static org.czeal.rfc3986.Utils.newIAE;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * <p>
 * Validates the {@code host} component of a URI reference as an IPv4 address according
 * to the syntax defined in <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">
 * RFC 3986, Appendix A. Collected ABNF for URI</a> as follows.
 * </p>
 *
 * <blockquote>
 * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
 * IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
 * dec-octet   = DIGIT                 ; 0-9
 *             / %x31-39 DIGIT         ; 10-99
 *             / "1" 2DIGIT            ; 100-199
 *             / "2" %x30-34 DIGIT     ; 200-249
 *             / "25" %x30-35          ; 250-255
 * }</pre>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 *      Appendix A. Collected ABNF for URI</a>
 *
 * @author Hideki Ikeda
 */
class Ipv4AddressValidator
{
    /**
     * Validates the {@code host} component of a URI reference as an IPv4 address.
     *
     * @param ipv4Address
     *         An IPv4 address value.
     *
     * @throws IllegalArgumentException
     *         If the IPv4 address is invalid.
     */
    void validate(String ipv4Address)
    {
        // Divide the host value by periods.
        String[] decOctets = ipv4Address.split("\\.", -1);

        // Ensure the host value contains four octets.
        if (decOctets.length != 4)
        {
            throw newIAE(
                "The host value \"%s\" is invalid as an IPv4 address because the " +
                "number of octets contained in the host is invalid.", ipv4Address);
        }

        // Ensure each part is a dec-octet.
        for (int i = 0; i < 4; i++)
        {
            validateDecOctet(decOctets[i], ipv4Address);
        }
    }


    private void validateDecOctet(String decOctet, String value)
    {
        // Ensure the dec-octet is not empty.
        if (decOctet.isEmpty())
        {
            throw newIAE(
                "The host value \"%s\" is invalid as an IPv4 address because it " +
                "contain an empty octet.", value);
        }

        // The length of the dec-octet. Expected to be either 1, 2, or 3.
        int length = decOctet.length();

        if (length == 1)
        {
            // Check the dec-octet as a single digit number.
            validateSingleDigitDecOctet(decOctet, value);
            return;
        }

        if (length == 2)
        {
            // Check the dec-octet as a two digit number.
            validateTwoDigitDecOctet(decOctet, value);
            return;
        }

        if (length == 3)
        {
            // Check the dec-octet as a three digit number.
            validateThreeDigitDecOctet(decOctet, value);
            return;
        }

        // The dec-octet is too long.
        throw newIAE(
            "The host value \"%s\" is invalid as an IPv4 address because the octet " +
            "\"%s\" has more than 3 characters.", value, decOctet);
    }


    private void validateSingleDigitDecOctet(String decOctet, String rawHost)
    {
        // Ensure the first digit is within the range of '0-9'.
        ensureDecOctetDigit(rawHost, decOctet, 0);
    }


    private void validateTwoDigitDecOctet(String decOctet, String rawHost)
    {
        // Ensure the first digit is within the range of '0-9'.
        ensureDecOctetDigit(rawHost, decOctet, 0);

        // Ensure the second digit is within the range of '0-9'.
        ensureDecOctetDigit(rawHost, decOctet, 1);
    }


    private void validateThreeDigitDecOctet(String decOctet, String rawHost)
    {
        // The first digit.
        char firstDigit = decOctet.charAt(0);

        if (firstDigit == '1')
        {
            // The first digit is '1'. Validate the remaining digits.
            validateThreeDigitDecOctetStartingWithOne(decOctet, rawHost);
            return;
        }

        if (firstDigit == '2')
        {
            // The first digit is '2'. Validate the remaining digits
            validateThreeDigitDecOctetStartingWithTwo(decOctet, rawHost);
            return;
        }

        // The first digit must start with '1' or '2'.
        throw invalidDecOctet(rawHost, decOctet, firstDigit, 0);
    }


    private void validateThreeDigitDecOctetStartingWithOne(
        String decOctet, String rawHost)
    {
        // Ensure the second digit is within the range of '0-9'.
        ensureDecOctetDigit(rawHost, decOctet, 1);

        // Ensure the third digit is within the range of '0-9'.
        ensureDecOctetDigit(rawHost, decOctet, 2);
    }


    private void validateThreeDigitDecOctetStartingWithTwo(
        String decOctet, String rawHost)
    {
        // The second digit.
        char secondDigit = decOctet.charAt(1);

        // If the second digit in the range from '0' to '4'.
        if (isInRange(secondDigit, '0', '4'))
        {
            // Ensure the third digit is within the range from '0' to '9'.
            ensureDecOctetDigit(rawHost, decOctet, 2);
            return;
        }

        // If the second digit is '5'.
        if (secondDigit == '5')
        {
            // Ensure the third digit is within the range from '0' to '5'.
            ensureDecOctetInRangeFromZeroToFive(rawHost, decOctet, 2);
            return;
        }

        // The second digit must be within the range from '0' to '5'.
        throw invalidDecOctet(rawHost, decOctet, secondDigit, 1);
    }


    private void ensureDecOctetDigit(String rawHost, String decOctet, int index)
    {
        // The digit at the index in the dec-octet.
        char digit = decOctet.charAt(index);

        // Ensure that the digit is within the range from '0' to '9'.
        if (!isDigit(digit))
        {
            throw invalidDecOctet(rawHost, decOctet, digit, index);
        }
    }


    private void ensureDecOctetInRangeFromZeroToFive(
        String rawHost, String decOctet, int index)
    {
        // The digit at the index in the dec-octet.
        char digit = decOctet.charAt(index);

        // Ensure that the digit is within the range from '0' to '5'.
        if (!isInRange(digit, '0', '5'))
        {
            throw invalidDecOctet(rawHost, decOctet, digit, index);
        }
    }


    private IllegalArgumentException invalidDecOctet(
        String rawHost, String decOctet, char digit, int index)
    {
        return newIAE(
            "The host value \"%s\" is invalid as an IPv4 address because the octet " +
            "\"%s\" has an invalid character \"%s\" at the index %d.", rawHost,
            decOctet, digit, index);
    }
}
