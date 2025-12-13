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


import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * <i>NOTE: This class is intended for internal use only.</i>
 *
 * <p>Utility class.</p>
 *
 * @author Hideki Ikeda
 */
class Utils
{
    /**
     * Checks whether a character is in a range or not.
     *
     * @param c
     *         A character.
     *
     * @param start
     *         The first character in the range.
     *
     * @param end
     *         The last character in the range.
     *
     * @return
     *         {@code true} if the character is in a range; otherwise, {@code false}.
     */
    static boolean isInRange(char c, char start, char end)
    {
        return start <= c && c <= end;
    }


    /**
     * Checks whether o nor a character is a digit (0-9).
     *
     * @param c
     *         A character.
     *
     * @return
     *         {@code true} if the character is a digit (0-9); otherwise, {@code false}.
     */
    static boolean isDigit(char c)
    {
        return isInRange(c, '0', '9');
    }


    /**
     * Checks whether o nor a character is an alphabet.
     *
     * @param c
     *         A character.
     *
     * @return
     *        {@code true} if the character is an alphabet; otherwise, {@code false}.
     */
    static boolean isAlphabet(char c)
    {
        return isInRange(c, 'a', 'z') || isInRange(c, 'A', 'Z');
    }


    /**
     * Checks whether or not a character is an unreserved character, as defined
     * in <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
     * Appendix A. Collected ABNF for URI</a>.
     *
     * <blockquote>
     * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
     * unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
     * }</pre>
     * </blockquote>
     *
     * @param c
     *         A character.
     *
     * @return
     *         {@code true} if the character is an unreserved character; otherwise,
     *         {@code false}.
     */
    static boolean isUnreserved(char c)
    {
        return isAlphabet(c) ||
               isDigit(c)    ||
               c == '-'      ||
               c == '.'      ||
               c == '_'      ||
               c == '~';
    }


    /**
     * Checks whether or not a character is a sub-delimiter, as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
     * Appendix A. Collected ABNF for URI</a> as follows.
     *
     * <blockquote>
     * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
     * subdelim = "!" / "$" / "&" / "'" / "(" / ")"
     *          / "*" / "+" / "," / ";" / "="
     * }
     * </pre>
     * </blockquote>
     *
     * @param c
     *         A character.
     *
     * @return
     *         {@code true} if the character is a sub-delimiter; otherwise, {@code false}.
     */
    static boolean isSubdelim(char c)
    {
        return c == '!'  ||
               c == '$'  ||
               c == '&'  ||
               c == '\'' ||
               c == '('  ||
               c == ')'  ||
               c == '*'  ||
               c == '+'  ||
               c == ','  ||
               c == ';'  ||
               c == '=';
    }


    /**
     * Checks whether or not a character is a hexadecimal digit.
     *
     * @param c
     *         A character.
     *
     * @return
     *         {@code true} if the character is a hexadecimal digit; otherwise,
     *         {@code false}.
     */
    static boolean isHexDigit(char c)
    {
        return isDigit(c)             ||
               isInRange(c, 'a', 'f') ||
               isInRange(c, 'A', 'F');
    }


    /**
     * A string containing all valid hexadecimal digits (0-9, A-F).
     */
    private static final String HEX_DIGITS = "0123456789ABCDEF";


    /**
     * Converts an integer to its equivalent hexadecimal digit.
     *
     * <p>
     * This method takes an integer {@code i} in the range of 0 to 15 (inclusive)
     * and returns the corresponding hexadecimal character from the standard set
     * of hexadecimal digits (0-9, A-F).
     * </p>
     *
     * @param i
     *         The integer to convert to a hexadecimal character.
     *
     * @return
     *         The hexadecimal character representation of {@code i} if {@code i}
     *         is in the valid range (0-15).
     *
     * @throws IllegalArgumentException
     *         If {@code i} is less than 0 or greater than 15.
     */
    static char toHexDigit(int i)
    {
        if (i < 0)
        {
            throw newIAE("The input integer is less than 0.");
        }

        if (i > 16)
        {
            throw newIAE("The input integer is larger than 16.");
        }

        return HEX_DIGITS.charAt(i);
    }


    /**
     * Converts a hexadecimal digit to its equivalent integer value.
     *
     * @param c
     *         The hexadecimal character to convert.
     *  i
     * @return
     *         The integer value of the hexadecimal character, or -1 if 'c' is not
     *         a valid hexadecimal character.
     */
    static int fromHexDigit(char c)
    {
        if ('0' <= c && c <= '9')
        {
            return c - '0';
        }

        if ('a' <= c && c <= 'f')
        {
            return 10 + c - 'a';
        }

        if ('A' <= c && c <= 'F')
        {
            return 10 + c - 'A';
        }

        return -1;
    }


    /**
     * Removes dot segments from the given path as stated in
     * <a href="https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4">"RFC 3986,
     * 5.2.4. Remove Dot Segments"</a>.
     *
     * @param path
     *         The path from which dot segments are to be removed.
     *
     * @return
     *         The path from which dot segments are removed.
     */
    static String removeDotSegments(String path)
    {
        // Initialize the input with the no-appended path components and the output
        // with the empty string.
        String input  = path;
        String output = "";

        // While the input is not empty, loop the following steps.
        while (input.length() > 0)
        {
            // If the input begins with a prefix of "../" or "./", then
            // remove that prefix from the input;
            Matcher m = Pattern.compile("^\\.?\\.\\/").matcher(input);
            if (m.find())
            {
                input = m.replaceFirst("");
                continue;
            }

            // If the input begins with a prefix of "/./" or "/.", where
            // "." is a complete path segment, then replace that prefix
            // with "/" in the input.
            m = Pattern.compile("^\\/\\.(\\/|$)").matcher(input);
            if (m.find())
            {
                input = m.replaceFirst("/");
                continue;
            }

            // If the input begins with a prefix of "/../" or "/..",
            // where ".." is a complete path segment, then replace that
            // prefix with "/" in the input and remove the last segment
            // and its preceding "/" (if any) from the output.
            m = Pattern.compile("^\\/\\.\\.(\\/|$)").matcher(input);
            if (m.find())
            {
                input = m.replaceFirst("/");
                output = dropLastSegment(output, true);
                continue;
            }

            // If the input consists only of "." or "..", then remove
            // that from the input.
            m = Pattern.compile("^\\.?\\.$").matcher(input);
            if (m.find())
            {
                input = m.replaceFirst("");
                continue;
            }

            // Move the first path segment in the input buffer to the
            // end of the output, including the initial "/" character
            // (if any) and any subsequent characters up to, but not
            // including, the next "/" character or the end of the input.
            m = Pattern.compile("^(?<firstsegment>\\/?[^/]*)(?<remaining>.*)$")
                       .matcher(input);
            if (m.find())
            {
                input   = m.group("remaining");
                output += m.group("firstsegment");
                continue;
            }
        }

        return output;
    }


    /**
     * Drops the last segment (= characters after the last slash) of a path and
     * optionally the last slash. If the path doesn't contain slash, an empty string
     * is returned.
     *
     * @param path
     *         The path.
     *
     * @param dropLastSlash
     *         Whether or not to drop the last slash if present.
     *
     * @return The path from which the last segment is removed.
     */
    static String dropLastSegment(String path, boolean dropLastSlash)
    {
        // The regular expression for the target.
        String regex = dropLastSlash ? "\\/?[^/]*$" : "[^/]*$";

        // Get a matcher for the pattern.
        Matcher m = Pattern.compile(regex).matcher(path);

        // Find the target. (Any inputs matches the pattern.)
        m.find();

        // Drop the target.
        return m.replaceFirst("");
    }


    /**
     * Create an {@code NullPointerException} with the given message.
     *
     * @param msg
     *         The error message.
     *
     * @param args
     *         The arguments referenced by the error message.
     *
     * @return
     *         An {@code NullPointerException} with the given message.
     */
    static NullPointerException newNPE(String msg, Object... args)
    {
        return new NullPointerException(String.format(msg, args));
    }


    /**
     * Create an {@code IllegalArgumentException} with the given message.
     *
     * @param msg
     *         The error message.
     *
     * @param args
     *         The arguments referenced by the error message.
     *
     * @return
     *         An {@code IllegalArgumentException} with the given message.
     */
    static IllegalArgumentException newIAE(String msg, Object... args)
    {
        return new IllegalArgumentException(String.format(msg, args));
    }


    /**
     * Create an {@code IllegalStateException} with the given message.
     *
     * @param msg
     *         The error message.
     *
     * @param args
     *         The arguments referenced by the error message.
     *
     * @return
     *         An {@code IllegalStateException} with the given message.
     */
    static IllegalStateException newISE(String msg, Object... args)
    {
        return new IllegalStateException(String.format(msg, args));
    }
}
