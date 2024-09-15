package com.github.subreption.yara.external;

import com.github.subreption.yara.Utils;
import com.github.subreption.yara.YaraMatch;
import com.github.subreption.yara.YaraString;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static com.github.subreption.yara.Preconditions.checkArgument;

public class YaraStringImpl implements YaraString {
    private String identifier;
    private List<YaraMatch> matches = new ArrayList<>();

    public YaraStringImpl(String identifier) {
        checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
    }

    public void addMatch(long offset, String value) {
        this.matches.add(new YaraMatchImpl(offset, value));
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public Iterator<YaraMatch> getMatches() {
        return matches.iterator();
    }
}
