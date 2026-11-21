/* Keep runtime entry points together and each kernel body beside its resumes. */
SECTIONS
{
    .text.osrec : { *(SORT_BY_NAME(.text.osrec.*)) }
}
INSERT AFTER .text;
