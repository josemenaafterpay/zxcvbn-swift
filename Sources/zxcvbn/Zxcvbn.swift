import czxcvbn
import Foundation

public enum Zxcvbn {
    public struct Match {
        public let begin: Int
        public let length: Int
        public let entropy: Double
        public let type: MatchType
    }

    public enum MatchType: UInt32 {
        case nonMatch = 0
        case bruteMatch = 1
        case dictionaryMatch = 2
        case dictLeetMatch = 3
        case userMatch = 4
        case userLeetMatch = 5
        case repeatsMatch = 6
        case sequenceMatch = 7
        case spatialMatch = 8
        case dateMatch = 9
        case yearMatch = 10
        case multipleMatch = 32
    }

    public struct Result {
        public let entropy: Double
        public let score: Int
        public let matches: [Match]
    }

    public static func estimate(_ password: String, userInfo: [String] = []) -> Result {
        var info: UnsafeMutablePointer<ZxcMatch_t>?

        defer {
            ZxcvbnFreeInfo(info)
        }

        guard !userInfo.isEmpty else {
            let entropy = ZxcvbnMatch(password, nil, &info)
            let crackTime = entropyToCrackTime(Float(entropy))
            let score = crackTimeToScore(seconds: crackTime)
            return Result(entropy: entropy, score: score, matches: convertInfo(info?.pointee))
        }

        return withArrayOfCStrings(userInfo) { userInfo in
            let entropy = ZxcvbnMatch(password, userInfo, &info)
            let crackTime = entropyToCrackTime(Float(entropy))
            let score = crackTimeToScore(seconds: crackTime)
            return Result(entropy: entropy, score: score, matches: convertInfo(info?.pointee))
        }
    }
}

private func convertInfo(_ info: ZxcMatch_t?) -> [Zxcvbn.Match] {
    var result = [Zxcvbn.Match]()
    var current = info

    while current != nil {
        let match = Zxcvbn.Match(
            begin: Int(current!.Begin),
            length: Int(current!.Length),
            entropy: current!.Entrpy,
            type: Zxcvbn.MatchType(rawValue: current!.Type.rawValue) ?? .nonMatch)
        result.append(match)

        current = current!.Next?.pointee
    }

    return result
}

private func withArrayOfCStrings<R>(_ args: [String], _ body: (UnsafeMutablePointer<UnsafePointer<CChar>?>) -> R) -> R {
    let argsCounts = Array(args.map { $0.utf8.count + 1 })
    let argsOffsets = [ 0 ] + scan(argsCounts, 0, +)
    let argsBufferSize = argsOffsets.last!

    var argsBuffer: [UInt8] = []
    argsBuffer.reserveCapacity(argsBufferSize)
    for arg in args {
        argsBuffer.append(contentsOf: arg.utf8)
        argsBuffer.append(0)
    }

    return argsBuffer.withUnsafeMutableBufferPointer {
        (argsBuffer) in
        let ptr = UnsafeMutableRawPointer(argsBuffer.baseAddress!).bindMemory(to: CChar.self, capacity: argsBuffer.count)
        var cStrings: [UnsafePointer<CChar>?] = argsOffsets.map { UnsafePointer(ptr + $0) }
        cStrings[cStrings.count - 1] = nil

        return cStrings.withUnsafeMutableBufferPointer { buf in body(buf.baseAddress!) }
    }
}

/// Compute the prefix sum of `seq`.
private func scan<S : Sequence, U>(_ seq: S, _ initial: U, _ combine: (U, S.Iterator.Element) -> U) -> [U] {
    var result: [U] = []
    result.reserveCapacity(seq.underestimatedCount)
    var runningResult = initial
    for element in seq {
        runningResult = combine(runningResult, element)
        result.append(runningResult)
    }
    return result
}

// Code copied from dropbox zxcvbn-ios
private func entropyToCrackTime(_ entropy: Float) -> Float {

    /*
     threat model -- stolen hash catastrophe scenario
     assumes:
     * passwords are stored as salted hashes, different random salt per user.
        (making rainbow attacks infeasable.)
     * hashes and salts were stolen. attacker is guessing passwords at max rate.
     * attacker has several CPUs at their disposal.
     * for a hash function like bcrypt/scrypt/PBKDF2, 10ms per guess is a safe lower bound.
     * (usually a guess would take longer -- this assumes fast hardware and a small work factor.)
     * adjust for your site accordingly if you use another hash function, possibly by
     * several orders of magnitude!
     */

    let singleGuess: Float = 0.010
    let numAttackers: Float = 100

    let secondsPerGuess =  singleGuess / numAttackers

    return 0.5 * pow(2, entropy) * secondsPerGuess
}

private func crackTimeToScore(seconds: Float) -> Int {
    if seconds < pow(10, 2) {
        return 0
    }

    if seconds < pow(10, 4) {
        return 1
    }

    if seconds < pow(10, 6) {
        return 2
    }

    if seconds < pow(10, 8) {
        return 3;
    }

    return 4;
}
