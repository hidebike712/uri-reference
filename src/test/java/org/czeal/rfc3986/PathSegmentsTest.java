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


import static org.czeal.rfc3986.TestUtils.assertThrowsNPE;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;


public class PathSegmentsTest
{
    @Test
    public void test_parse()
    {
        assertDoesNotThrow(() -> PathSegments.parse("/a/b/c"));
        assertDoesNotThrow(() -> PathSegments.parse("/"));
        assertDoesNotThrow(() -> PathSegments.parse(""));
        assertDoesNotThrow(() -> PathSegments.parse(null));
    }


    @Test
    public void test_add()
    {
        assertDoesNotThrow(() -> PathSegments.parse("/a/b/c").add("d", "e"));
        assertDoesNotThrow(() -> PathSegments.parse("/a/b/c").add(""));

        assertThrowsNPE(
            "The segments must not be null.",
            () -> PathSegments.parse("/a/b/c").add((String[])null));

        assertThrowsNPE(
            "A segment must not be null.",
            () -> PathSegments.parse("/a/b/c").add(new String[]{ null }));
    }


    @Test
    public void test_toString()
    {
        assertEquals("/a/b/c", PathSegments.parse("/a/b/c").toString());
        assertEquals("/a/b/c/d/e", PathSegments.parse("/a/b/c").add("d", "e").toString());
    }
}
