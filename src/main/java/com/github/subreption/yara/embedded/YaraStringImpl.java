package com.github.subreption.yara.embedded;

import com.github.subreption.yara.GenericIterator;
import com.github.subreption.yara.YaraMatch;
import com.github.subreption.yara.YaraString;

import java.util.Iterator;

import static com.github.subreption.yara.Preconditions.checkArgument;

/**
 * Yara rule strings
 */
public class YaraStringImpl implements YaraString {
    private final YaraLibrary library;
    private final long context;
    private final long peer;

    YaraStringImpl(YaraLibrary library, long context, long peer) {
        checkArgument(library != null);
        checkArgument(context != 0);
        checkArgument(peer != 0);

        this.library = library;
        this.context = context;
        this.peer = peer;
    }

    /**
     * Get identifier
     *
     * @return
     */
    public String getIdentifier() {
        return library.stringIdentifier(peer);
    }

    /**
     * Get matches for the string
     *
     * @return
     */
    public Iterator<YaraMatch> getMatches() {
        return new GenericIterator<YaraMatch>() {
            private long index = library.stringMatches(context, peer);

            @Override
            protected YaraMatchImpl getNext() {
                if (index == 0) {
                    return null;
                }

                long last = index;
                index = library.stringMatchNext(index);

                return new YaraMatchImpl(library, last);
            }
        };
    }
}
