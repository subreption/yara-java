#ifndef __LIBYARA_H__
#define __LIBYARA_H__

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

#include "yara.h"
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif


static jstring
cast_jstring(JNIEnv *env, const char * v) {
    return !v ?NULL :
            (*env)->NewStringUTF(env, v);
}

/*
 * Rule indentifier
 */
static jstring
yara_rule_identifier(JNIEnv *env, void *v) {
    return !v ? NULL :
            cast_jstring(env, ((YR_RULE*)v)->identifier);
}

/*
 *  Tag iteration
 */
static void*
yara_rule_tags(JNIEnv *env, void *v) {
    return !v ? 0 : (void *)((YR_RULE*)v)->tags;
}

static void*
yara_rule_tag_next(JNIEnv *env, void *v) {
    char *n = v;

    if (!n || *n == '\0') {
        return 0;
    }

    for ( ; *n != '\0'; ++n);
    return n + 1;
}

static jstring
yara_tag_string(JNIEnv *env, void *v) {
    return !v ? NULL :
            cast_jstring(env, (char*)v);
}

/*
 *  Metadata iteration
 */
static void*
yara_rule_metas(JNIEnv *env, void *v) {
    return !v ? 0 : ((YR_RULE*)v)->metas;
}

static void*
yara_rule_meta_next(JNIEnv *env, void *v) {
    YR_META *meta = (YR_META *)v;

    if (NULL == meta) {
        return 0;
    }
    return META_IS_LAST_IN_RULE(meta) ? NULL : ++meta;
}

static int
yara_meta_type(JNIEnv *env, void* v) {
    return !v ? 0 : ((YR_META*)v)->type;
}

static jstring
yara_meta_identifier(JNIEnv *env, void *v) {
    return !v ? NULL :
            cast_jstring(env, ((YR_META*)v)->identifier);
}

static jstring
yara_meta_string(JNIEnv *env, void *v) {
    return !v ? NULL :
            cast_jstring(env, ((YR_META*)v)->string);
}

static int
yara_meta_integer(JNIEnv *env, void *v) {
    return !v ? 0 : ((YR_META*)v)->integer;
}

/*
 *  Strings iteration
 */
static void*
yara_rule_strings(JNIEnv *env, void *v) {
    return !v ? 0 : ((YR_RULE*)v)->strings;
}

static void*
yara_rule_string_next(JNIEnv *env, void *v) {
    YR_STRING *string = (YR_STRING *)v;

    if (NULL == string) {
        return 0;
    }
    return STRING_IS_LAST_IN_RULE(string) ? NULL : ++string;
}

static jstring
yara_string_identifier(JNIEnv *env, void *v) {
    return !v ? NULL :
            cast_jstring(env, ((YR_STRING*)v)->identifier);
}

static void*
yara_string_matches(JNIEnv *env, void *context, void *v) {
    YR_STRING *string = (YR_STRING *)v;
    YR_MATCHES* matches = ((YR_SCAN_CONTEXT*)context)->matches;
    return matches[string->idx].head;
}

static void*
yara_string_match_next(JNIEnv *env, void *v) {
    YR_MATCH *match = (YR_MATCH *)v;

    if(NULL == match) {
        return 0;
    }

    while(match->is_private){
        match = match->next;
    }

    return match->next;
}

static int64_t
yara_match_offset(JNIEnv *env, void *v) {
    return !v ? 0:
            ((YR_MATCH*)v)->offset;
}

static jstring
yara_match_value(JNIEnv *env, void *v) {
    char *buffer = 0;
    YR_MATCH *match = (YR_MATCH *)v;
    jstring value = 0;

    if (!v) {
        return 0;
    }

    if (0 != (buffer = malloc(match->data_length + 1))) {
        memset(buffer, 0, match->data_length + 1);
        strncpy(buffer, (const char* )match->data, match->data_length);

        value = cast_jstring(env, buffer);

        free(buffer);
    }

    return value;
}

/* Object is used as workaround for a bug in hawtjni */
static jobject
yara_match_bytes(JNIEnv *env, void *v) {
    YR_MATCH *match = (YR_MATCH *)v;
    jbyteArray value;

    if (!v) {
        return 0;
    }

    value = (*env)->NewByteArray(env, match->data_length);
    if (value == NULL)
        return NULL;

    // Copy the bytes from YR_MATCH's data into the Java byte array
    (*env)->SetByteArrayRegion(env, value, 0, match->data_length, (const jbyte*)match->data);

    return value;
}

/*
 *  Compilation
 */
static int
yara_compiler_add_file(JNIEnv *env, void *compiler, const char *path, const char *ns, const char *file_name) {
    FILE *fp = fopen(path, "r");
    int ret = 0;

    if (fp) {
        ret = yr_compiler_add_file((YR_COMPILER*)compiler, fp, ns, file_name);
        fclose(fp);
    }
    else {
        ret = 3;
    }

    return ret;
}

/*
 *  Module functions
 */
static jstring
yara_module_name(JNIEnv *env, void *v) {
    YR_MODULE_IMPORT *mod = (YR_MODULE_IMPORT *)v;


    return !mod || !mod->module_name ? NULL :
        cast_jstring(env, (char*)mod->module_name);
}

static int64_t
yara_module_load_data(JNIEnv *env, void *pv, const char *path) {
    YR_MAPPED_FILE   *mp  = 0;
    YR_MODULE_IMPORT *mod = (YR_MODULE_IMPORT *)pv;

    if (mod) {
        mp = malloc(sizeof(YR_MAPPED_FILE));

        if (ERROR_SUCCESS == yr_filemap_map(path, mp)) {
            mod->module_data = mp->data;
            mod->module_data_size = mp->size;
        }
        else {
            free(mp);
            mp = 0;
        }
    }

    return (int64_t)mp;
}

static void
yara_module_unload_data(JNIEnv *env, void *pv) {
    YR_MAPPED_FILE *mp = (YR_MAPPED_FILE *)pv;

    if (mp) {
        yr_filemap_unmap(mp);
    }
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
