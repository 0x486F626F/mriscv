MEMORY
{
    FLASH : ORIGIN = 0x00100000, LENGTH = 1M
    RAM : ORIGIN = 0x00200000, LENGTH = 32M
}

REGION_ALIAS("REGION_TEXT", FLASH);
REGION_ALIAS("REGION_RODATA", FLASH);
REGION_ALIAS("REGION_DATA", RAM);
REGION_ALIAS("REGION_BSS", RAM);
REGION_ALIAS("REGION_HEAP", RAM);
REGION_ALIAS("REGION_STACK", RAM);
