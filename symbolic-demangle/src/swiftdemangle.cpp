#include "swift/Demangling/Demangle.h"
#include "swift/Demangling/Demangler.h"

#define SYMBOLIC_SWIFT_FEATURE_RETURN_TYPE 0x1
#define SYMBOLIC_SWIFT_FEATURE_PARAMETERS 0x2
#define SYMBOLIC_SWIFT_FEATURE_ALL 0x3

extern "C" int symbolic_demangle_swift(const char *symbol,
                                       char *buffer,
                                       size_t buffer_length,
                                       int features) {
    swift::Demangle::DemangleOptions opts;

    if (features < SYMBOLIC_SWIFT_FEATURE_ALL) {
        opts = swift::Demangle::DemangleOptions::SimplifiedUIDemangleOptions();
        bool return_type = features & SYMBOLIC_SWIFT_FEATURE_RETURN_TYPE;
        bool argument_types = features & SYMBOLIC_SWIFT_FEATURE_PARAMETERS;

        opts.ShowFunctionReturnType = return_type;
        opts.ShowFunctionArgumentTypes = argument_types;
    }

    std::string demangled =
        swift::Demangle::demangleSymbolAsString(llvm::StringRef(symbol), opts);

    if (demangled.size() == 0 || demangled.size() >= buffer_length) {
        return false;
    }

    memcpy(buffer, demangled.c_str(), demangled.size());
    buffer[demangled.size()] = '\0';
    return true;
}

extern "C" int symbolic_demangle_is_swift_symbol(const char *symbol) {
    return swift::Demangle::isSwiftSymbol(symbol);
}

extern "C" int symbolic_demangle_swift_type(const char *symbol,
                                            char *buffer,
                                            size_t buffer_length) {
    try {
        swift::Demangle::NodeFactory factory;
        factory.setAllocationLimit(256 * 1024);
        auto *root =
            swift::Demangle::demangleOldSymbolAsNode(symbol, factory, 64);
        if (!root || root->getKind() != swift::Demangle::Node::Kind::Global ||
            root->getNumChildren() != 1 ||
            root->getFirstChild()->getKind() !=
                swift::Demangle::Node::Kind::TypeMangling)
            return false;

        swift::Demangle::DemangleOptions options;
        swift::Demangle::NodePrinter printer(options, 4096, 64, 16384);
        printer.printRoot(root);
        std::string demangled = printer.takeString();
        if (demangled.empty() || demangled.size() >= buffer_length)
            return false;
        memcpy(buffer, demangled.c_str(), demangled.size());
        buffer[demangled.size()] = '\0';
        return true;
    } catch (const std::exception &) {
        return false;
    }
}
