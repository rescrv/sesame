/* this is inspired by or copied from Beautiful Code (chap 1?) */

/* C */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

static int
anchored(const char* regex, const char* regex_end,
         const char* text,  const char* text_end);

static int
starred(int c,
        const char* regex, const char* regex_end,
        const char* text,  const char* text_end);

int
anchored(const char* regex, const char* regex_end,
         const char* text,  const char* text_end)
{
    assert(regex <= regex_end);
    assert(text <= text_end);

    if (regex == regex_end)
    {
        return 1;
    }

    if (regex[0] == '\\')
    {
        if (regex + 1 < regex_end &&
            text < text_end &&
            regex[1] == text[0])
        {
            return anchored(regex + 2, regex_end, text + 1, text_end);
        }

        return 0;
    }

    if (regex + 1 < regex_end && regex[1] == '*')
    {
        return starred(regex[0], regex + 2, regex_end, text, text_end);
    }

    if (regex[0] == '$' && regex + 1 == regex_end)
    {
        return text == text_end;
    }

    if (text < text_end && (regex[0] == '.' || regex[0] == text[0]))
    {
        return anchored(regex + 1, regex_end, text + 1, text_end);
    }

    return 0;
}

int
starred(int c,
        const char* regex, const char* regex_end,
        const char* text,  const char* text_end)
{
    for (; text <= text_end; ++text)
    {
        if (anchored(regex, regex_end, text, text_end))
        {
            return 1;
        }

        if (text < text_end && *text != c && c != '.')
        {
            break;
        }
    }

    return 0;
}

int
regex_match(const char* regex, size_t regex_sz,
            const char* text, size_t text_sz)
{
    const char* regex_end = regex + regex_sz;
    const char* text_end  = text + text_sz;

    if (regex_sz == 0)
    {
        return 1;
    }

    if (regex[0] == '^')
    {
        return anchored(regex + 1, regex_end, text, text_end);
    }

    for (; text <= text_end; ++text)
    {
        if (anchored(regex, regex_end, text, text_end))
        {
            return 1;
        }
    }

    return 0;
}
