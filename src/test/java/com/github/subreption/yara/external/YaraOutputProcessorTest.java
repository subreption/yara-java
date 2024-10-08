/*
 * Copyright (c) 2024 Subreption LLC. All rights reserved.
 * Copyright (c) 2015-2022 Paul Apostolescu. All rights reserved.
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

package com.github.subreption.yara.external;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.mock;

import com.github.subreption.yara.YaraMatch;
import com.github.subreption.yara.YaraMeta;
import com.github.subreption.yara.YaraRule;
import com.github.subreption.yara.YaraScanCallback;
import com.github.subreption.yara.YaraString;


/**
 * User: pba
 * Date: 6/16/15
 * Time: 3:56 PM
 */
public class YaraOutputProcessorTest {
    @Test
    public void testCreateNull() {
        assertThrows(IllegalArgumentException.class, () -> new YaraOutputProcessor(null));
    }

    @Test
    public void testCreate() {
        new YaraOutputProcessor(mock(YaraScanCallback.class));
    }

    @Test
    public void testStartComplete() {
        YaraScanCallback callback = rule -> fail();

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onComplete();
    }

    @Test
    public void testRuleNoMeta() {
        final AtomicReference<YaraRule> captureRule = new AtomicReference<>();

        YaraScanCallback callback = captureRule::set;

        String value = "HelloWorld [] []";

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onLine(value);
        processor.onComplete();

        assertNotNull(captureRule.get());
        assertEquals("HelloWorld", captureRule.get().getIdentifier());
        assertFalse(captureRule.get().getMetadata().hasNext());
        assertFalse(captureRule.get().getStrings().hasNext());
    }

    @Test
    public void testRuleTags() {
        final AtomicReference<YaraRule> captureRule = new AtomicReference<>();

        YaraScanCallback callback = captureRule::set;

        String value = "HelloWorld [One,Two,Three] []";

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onLine(value);
        processor.onComplete();

        YaraRule rule = captureRule.get();

        assertNotNull(rule);
        assertEquals("HelloWorld", rule.getIdentifier());
        assertFalse(rule.getStrings().hasNext());

        Iterator<String> tags = rule.getTags();
        assertEquals("One",tags.next());
        assertEquals("Two",tags.next());
        assertEquals("Three",tags.next());
        assertFalse(tags.hasNext());

        Iterator<YaraMeta> metas = rule.getMetadata();
        assertFalse(metas.hasNext());
    }

    @Test
    public void testRuleMeta() {
        final AtomicReference<YaraRule> captureRule = new AtomicReference<>();

        YaraScanCallback callback = captureRule::set;

        String value = "HelloWorld [] [name=\"InstallsDriver\",description=\"The file attempted to install a driver\"]";

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onLine(value);
        processor.onComplete();

        YaraRule rule = captureRule.get();

        assertNotNull(rule);
        assertEquals("HelloWorld", rule.getIdentifier());
        assertFalse(rule.getStrings().hasNext());

        Iterator<YaraMeta> metas = rule.getMetadata();

        YaraMeta meta = metas.next();
        assertEquals("name", meta.getIdentifier());
        assertEquals("InstallsDriver", meta.getString());

        meta = metas.next();
        assertEquals("description", meta.getIdentifier());
        assertEquals("The file attempted to install a driver", meta.getString());

        assertFalse(metas.hasNext());
    }

    @Test
    public void testRuleMetaAll() {
        final AtomicReference<YaraRule> captureRule = new AtomicReference<>();

        YaraScanCallback callback = captureRule::set;

        String value = "HelloWorld [] [string=\"String\",number=1,boolean=true]";

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onLine(value);
        processor.onComplete();

        YaraRule rule = captureRule.get();

        assertNotNull(rule);
        assertEquals("HelloWorld", rule.getIdentifier());
        assertFalse(rule.getStrings().hasNext());

        Iterator<YaraMeta> metas = rule.getMetadata();

        YaraMeta meta = metas.next();
        assertEquals("string", meta.getIdentifier());
        assertEquals("String", meta.getString());

        meta = metas.next();
        assertEquals("number", meta.getIdentifier());
        assertEquals(1, meta.getInteger());

        meta = metas.next();
        assertEquals("boolean", meta.getIdentifier());
        assertEquals(1, meta.getInteger());

        assertFalse(metas.hasNext());
    }

    @Test
    public void testRuleMetaUgly() {
        final AtomicReference<YaraRule> captureRule = new AtomicReference<>();

        YaraScanCallback callback = captureRule::set;

        String value = "HelloWorld [One] [name=\"InstallsDriver\"," +
                "description=\"The file attempted to install a driver\"," +
                "categories=\"Process \\\",= Creation\"," +
                "type=\"external\"," +
                "behaviors=\"InstallsDriver\"," +
                "output=\"([^\\\"]*)$\"," +
                "template=\"%s\"] test.bla";

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onLine(value);
        processor.onComplete();

        YaraRule rule = captureRule.get();

        Iterator<String> tags = rule.getTags();
        assertEquals("One", tags.next());
        assertFalse(tags.hasNext());

        assertNotNull(rule);
        assertEquals("HelloWorld", rule.getIdentifier());
        assertFalse(rule.getStrings().hasNext());

        Iterator<YaraMeta> metas = rule.getMetadata();

        YaraMeta meta = metas.next();
        assertEquals("name", meta.getIdentifier());
        assertEquals("InstallsDriver", meta.getString());

        meta = metas.next();
        assertEquals("description", meta.getIdentifier());
        assertEquals("The file attempted to install a driver", meta.getString());

        meta = metas.next();
        assertEquals("categories", meta.getIdentifier());
        assertEquals("Process \",= Creation", meta.getString());

        meta = metas.next();
        assertEquals("type", meta.getIdentifier());
        assertEquals("external", meta.getString());

        meta = metas.next();
        assertEquals("behaviors", meta.getIdentifier());
        assertEquals("InstallsDriver", meta.getString());

        meta = metas.next();
        assertEquals("output", meta.getIdentifier());
        assertEquals("([^\"]*)$", meta.getString());

        meta = metas.next();
        assertEquals("template", meta.getIdentifier());
        assertEquals("%s", meta.getString());

        assertFalse(metas.hasNext());
    }

    @Test
    public void testRuleMultiple() {
        final List<YaraRule> rules =new ArrayList<>();

        YaraScanCallback callback = rules::add;

        String[] lines = new String[] {
                "HelloWorld [] [name=\"InstallsDriver\",description=\"The file attempted to install a driver\"] test.bla",
                "0xf:$a: Hello World",
                "0x59:$a: Hello World",
                "HereIsATest [] [internal=true,value=123] test.bla",
                "0x20:$a: here",
                "0x52:$a: here"
        };

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        for (String line : lines) {
            processor.onLine(line);
        }
        processor.onComplete();

        assertEquals(2, rules.size());

        // HelloWorld rule
        YaraRule rule = rules.get(0);
        assertNotNull(rule);
        assertEquals("HelloWorld", rule.getIdentifier());

        // Hello world metas
        Iterator<YaraMeta> metas = rule.getMetadata();
        YaraMeta meta = metas.next();
        assertEquals("name", meta.getIdentifier());
        assertEquals("InstallsDriver", meta.getString());

        meta = metas.next();
        assertEquals("description", meta.getIdentifier());
        assertEquals("The file attempted to install a driver", meta.getString());

        // Hello world matches
        Iterator<YaraString> strings = rule.getStrings();
        YaraString string = strings.next();
        assertEquals("$a", string.getIdentifier());

        Iterator<YaraMatch> matches = string.getMatches();
        YaraMatch match = matches.next();
        assertEquals((long)Long.decode("0xf"), match.getOffset());
        assertEquals("Hello World", match.getValue());

        match = matches.next();
        assertEquals((long)Long.decode("0x59"), match.getOffset());
        assertEquals("Hello World", match.getValue());

        assertFalse(metas.hasNext());

        // Hereisatest rule
        rule = rules.get(1);
        assertNotNull(rule);
        assertEquals("HereIsATest", rule.getIdentifier());

        // Hereisatest  metas
        metas = rule.getMetadata();
        meta = metas.next();
        assertEquals("internal", meta.getIdentifier());
        assertEquals(1, meta.getInteger());

        meta = metas.next();
        assertEquals("value", meta.getIdentifier());
        assertEquals(123, meta.getInteger());

        // Hereisatest matches
        strings = rule.getStrings();
        string = strings.next();
        assertEquals("$a", string.getIdentifier());

        matches = string.getMatches();
        match = matches.next();
        assertEquals((long)Long.decode("0x20"), match.getOffset());
        assertEquals("here", match.getValue());

        match = matches.next();
        assertEquals((long)Long.decode("0x52"), match.getOffset());
        assertEquals("here", match.getValue());

        assertFalse(metas.hasNext());
    }
}
