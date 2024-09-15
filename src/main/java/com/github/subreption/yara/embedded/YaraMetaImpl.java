package com.github.subreption.yara.embedded;

import com.github.subreption.yara.YaraMeta;

import static com.github.subreption.yara.Preconditions.checkArgument;

/**
 * User: pba
 * Date: 6/9/15
 * Time: 3:06 PM
 */
public class YaraMetaImpl implements YaraMeta {


    private final YaraLibrary library;
    private final long peer;

    YaraMetaImpl(YaraLibrary library, long peer) {
        checkArgument(library != null);
        checkArgument(peer != 0);

        this.library = library;
        this.peer = peer;
    }

    public Type getType() {
        return Type.from(library.metaType(peer));
    }

    public String getIndentifier() {
        return library.metaIdentifier(peer);
    }

    public String getString() {
        return library.metaString(peer);
    }

    public int getInteger() {
        return library.metaInteger(peer);
    }
}
