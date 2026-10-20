//! Module-root wrapper for zhttp's native QPACK codec.
//!
//! `h3/native/qpack.zig` imports `../../h2/huffman.zig`, which is outside
//! that file's own directory. Zig permits the import only when the module
//! root sits at `src/`, so this file is the module root and re-exports the
//! names zoxy uses.

const inner = @import("h3/native/qpack.zig");

pub const Decoder = inner.Decoder;
pub const DecoderInstruction = inner.DecoderInstruction;
pub const DecoderInstructionValue = inner.DecoderInstructionValue;
pub const DecoderScan = inner.DecoderScan;
pub const DynamicTable = inner.DynamicTable;
pub const Encoder = inner.Encoder;
pub const EncoderApply = inner.EncoderApply;
pub const EncoderInstruction = inner.EncoderInstruction;
pub const EncoderScan = inner.EncoderScan;
pub const Error = inner.Error;
pub const HeaderField = inner.HeaderField;
pub const HeaderList = inner.HeaderList;
pub const applyEncoderInstruction = inner.applyEncoderInstruction;
pub const decode = inner.decode;
pub const encode = inner.encode;
pub const max_decoder_instruction_len = inner.max_decoder_instruction_len;
pub const peekRequiredInsertCount = inner.peekRequiredInsertCount;
pub const scanDecoderInstruction = inner.scanDecoderInstruction;
pub const scanEncoderInstruction = inner.scanEncoderInstruction;
pub const static_table = inner.static_table;
pub const writeDecoderInstruction = inner.writeDecoderInstruction;
