#include <trap/trap.h>
#include <Zydis/Zydis.h>
#include <sys/mman.h>
#include <cstring>
#include <memory>

#ifndef PAGE_SIZE
#define PAGE_SIZE       0x1000
#endif

#define ROUND_PG(x)     (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x)     ((x) & ~(PAGE_SIZE - 1))

/*
 * jump template:
 *      jmp *0(%rip)
 *      .dq address
 * */

constexpr unsigned char JUMP_TEMPLATE[] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

constexpr auto JUMP_GUIDE = 6;
constexpr auto TRAMPOLINE_SIZE = sizeof(JUMP_TEMPLATE);

static bool setProtection(void *address, size_t length, int protection) {
    uintptr_t start = TRUNC_PG((uintptr_t) address);
    uintptr_t end = ROUND_PG((uintptr_t) address + length);

    return mprotect((void *) start, end - start, protection) == 0;
}

int trap_hook(void *address, void *replace, void **backup) {
    ZydisDecoder decoder;

    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64)))
        return -1;

    size_t pos = 0;
    ZydisDecodedInstruction instruction;

    do {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
                &decoder,
                (std::byte *) address + pos,
                ZYDIS_MAX_INSTRUCTION_LENGTH + TRAMPOLINE_SIZE - pos,
                &instruction
        )))
            return -1;

        if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
            return -1;

        pos += instruction.length;
    } while (pos < TRAMPOLINE_SIZE);

    std::unique_ptr<std::byte[]> escape = std::make_unique<std::byte[]>(pos + TRAMPOLINE_SIZE);

    if (!setProtection(escape.get(), pos + TRAMPOLINE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC))
        return -1;

    memcpy(escape.get(), address, pos);
    memcpy(escape.get() + pos, JUMP_TEMPLATE, TRAMPOLINE_SIZE);

    *(void **) (escape.get() + pos + JUMP_GUIDE) = (std::byte *) address + pos;

    if (!setProtection(address, TRAMPOLINE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC))
        return -1;

    memcpy(address, JUMP_TEMPLATE, TRAMPOLINE_SIZE);
    *(void **) ((std::byte *) address + JUMP_GUIDE) = replace;

    if (!setProtection(address, TRAMPOLINE_SIZE, PROT_READ | PROT_EXEC))
        return -1;

    *backup = escape.release();

    return 0;
}

int trap_unhook(void *address, void *backup) {
    if (memcmp(address, JUMP_TEMPLATE, JUMP_GUIDE) != 0)
        return -1;

    if (!setProtection(address, TRAMPOLINE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC))
        return -1;

    memcpy(address, backup, TRAMPOLINE_SIZE);
    delete[](std::byte *) backup;

    if (!setProtection(address, TRAMPOLINE_SIZE, PROT_READ | PROT_EXEC))
        return -1;

    return 0;
}
