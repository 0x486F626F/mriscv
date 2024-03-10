MEMORY
{
    FLASH : ORIGIN = 0x20400000, LENGTH = 8M
    RAM : ORIGIN = 0x80000000, LENGTH = 32M
}

REGION_ALIAS("REGION_TEXT", FLASH);
REGION_ALIAS("REGION_RODATA", FLASH);
REGION_ALIAS("REGION_DATA", RAM);
REGION_ALIAS("REGION_BSS", RAM);
REGION_ALIAS("REGION_HEAP", RAM);
REGION_ALIAS("REGION_STACK", RAM);
