"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getRandomBytes = void 0;
const crypto_1 = require("crypto");
function getRandomBytes(numBytes) {
    return new Uint8Array((0, crypto_1.randomBytes)(numBytes).buffer);
}
exports.getRandomBytes = getRandomBytes;
//# sourceMappingURL=csprng.node.js.map