import Foundation
// sv has no Swift reader, so it cannot say what this file does or does not use.
func parse(_ data: Data) -> String { return String(decoding: data, as: UTF8.self) }
