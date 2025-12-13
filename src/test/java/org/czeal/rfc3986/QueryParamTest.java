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


public class QueryParamTest
{
    @Test
    public void test_parse()
    {
        assertDoesNotThrow(() -> QueryParam.parse("k=v"));
        assertDoesNotThrow(() -> QueryParam.parse("k="));
        assertDoesNotThrow(() -> QueryParam.parse("=v"));
        assertDoesNotThrow(() -> QueryParam.parse("k"));
        assertDoesNotThrow(() -> QueryParam.parse(""));
        assertDoesNotThrow(() -> QueryParam.parse("k=v=v"));
        assertThrowsNPE("The input string must not be null.", () -> QueryParam.parse(null));
    }


    @Test
    public void test_toString()
    {
        assertEquals("k=v", QueryParam.parse("k=v").toString());
        assertEquals("k=", QueryParam.parse("k=").toString());
        assertEquals("=v", QueryParam.parse("=v").toString());
        assertEquals("k", QueryParam.parse("k").toString());
        assertEquals("", QueryParam.parse("").toString());
        assertEquals("k=v=v", QueryParam.parse("k=v=v").toString());
    }


    @Test
    public void test_getKey()
    {
        assertEquals("k", QueryParam.parse("k=v").getKey());
        assertEquals("k", QueryParam.parse("k=").getKey());
        assertEquals("",  QueryParam.parse("=v").getKey());
        assertEquals("k", QueryParam.parse("k").getKey());
        assertEquals("",  QueryParam.parse("").getKey());
        assertEquals("k", QueryParam.parse("k=v=v").getKey());
    }


    @Test
    public void test_getValue()
    {
        assertEquals("v", QueryParam.parse("k=v").getValue());
        assertEquals("",  QueryParam.parse("k=").getValue());
        assertEquals("v", QueryParam.parse("=v").getValue());
        assertEquals((String)null, QueryParam.parse("k").getValue());
        assertEquals((String)null, QueryParam.parse("").getValue());
        assertEquals("v=v", QueryParam.parse("k=v=v").getValue());
    }
}
