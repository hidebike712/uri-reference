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


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.function.Executable;


public class TestUtils
{
    public static <T extends Throwable> void assertThrowsNPE(Executable executable)
    {
        assertThrowsNPE(null, executable);
    }


    public static <T extends Throwable> void assertThrowsNPE(
        String message, Executable executable)
    {
        assertThrowsException(NullPointerException.class, message, executable);
    }


    public static <T extends Throwable> void assertThrowsIAE(
        String message, Executable executable)
    {
        assertThrowsException(IllegalArgumentException.class, message, executable);
    }


    public static <T extends Throwable> void assertThrowsISE(
        String message, Executable executable)
    {
        assertThrowsException(IllegalStateException.class, message, executable);
    }


    public static <T extends Throwable> void assertThrowsException(
        Class<T> expectedType, String message, Executable executable)
    {
        // Assert the 'executable' throw an exception.
        T ex = assertThrows(expectedType, executable);

        // Ensure the exception is not null.
        assertNotNull(ex);

        // Ensure the message matches the expected one.
        if (message != null)
        {
            assertEquals(message, ex.getMessage());
        }
    }
}
