#include <fstream>
#include <iostream>

#include "KeyFinder.h"
#include "util.h"
#include "AddressUtil.h"

#include "Logger.h"


void KeyFinder::defaultResultCallback(KeySearchResult result)
{
	// Do nothing
}

void KeyFinder::defaultStatusCallback(KeySearchStatus status)
{
	// Do nothing
}

KeyFinder::KeyFinder(const secp256k1::uint256 &startKey, const secp256k1::uint256 &endKey, int compression, KeySearchDevice* device, const secp256k1::uint256 &stride)
{
	_total = 0;
	_statusInterval = 1000;
	_device = device;

	_compression = compression;

    _startKey = startKey;

    _endKey = endKey;

	_statusCallback = NULL;

	_resultCallback = NULL;

    _iterCount = 0;

    _stride = stride;
}

KeyFinder::~KeyFinder()
{
}

void KeyFinder::setTargets(std::vector<std::string> &targets)
{
	if(targets.size() == 0) {
		throw KeySearchException("Requires at least 1 target");
	}

	_targets.clear();

	// Convert each address from base58 (P2PKH) or bech32 (P2WPKH) to a 160-bit
	// integer. Both encodings commit to RIPEMD160(SHA256(pubkey)), which is
	// exactly what the GPU pipeline produces, so they can be matched against
	// the same target set.
	for(unsigned int i = 0; i < targets.size(); i++) {

		KeySearchTarget t;

		Address::Kind kind = Address::toHash160(targets[i], t.value);
		if(kind == Address::Kind::Unsupported) {
			throw KeySearchException("Invalid or unsupported address '" + targets[i] + "'");
		}

		_targets.insert(t);
	}

    _device->setTargets(_targets);
}

void KeyFinder::setTargets(std::string targetsFile)
{
	std::ifstream inFile(targetsFile.c_str());

	if(!inFile.is_open()) {
		Logger::log(LogLevel::Error, "Unable to open '" + targetsFile + "'");
		throw KeySearchException();
	}

	_targets.clear();

	std::string line;
	Logger::log(LogLevel::Info, "Loading addresses from '" + targetsFile + "'");

	uint64_t loadedP2PKH = 0;
	uint64_t loadedP2WPKH = 0;
	uint64_t skipped = 0;
	uint64_t lineNo = 0;

	while(std::getline(inFile, line)) {
		lineNo++;
		util::removeNewline(line);

		// The blockchair address dump is TSV ("address\tbalance"). Keep only
		// the first column so the same loader works for plain address lists
		// and for TSV files.
		size_t tab = line.find('\t');
		if(tab != std::string::npos) {
			line = line.substr(0, tab);
		}

        line = util::trim(line);

		// Allow blank lines and '#' comments.
		if(line.empty() || line[0] == '#') {
			continue;
		}

		KeySearchTarget t;
		Address::Kind kind = Address::toHash160(line, t.value);
		if(kind == Address::Kind::Unsupported) {
			skipped++;
			continue;
		}

		if(kind == Address::Kind::P2PKH) {
			loadedP2PKH++;
		} else if(kind == Address::Kind::P2WPKH) {
			loadedP2WPKH++;
		}

		_targets.insert(t);

		// Periodic progress log so loading a 58M-row TSV doesn't look frozen.
		if(((loadedP2PKH + loadedP2WPKH) & 0xFFFFF) == 0) {
			Logger::log(LogLevel::Info,
				"  ... " + util::formatThousands(loadedP2PKH + loadedP2WPKH)
				+ " addresses parsed");
		}
	}

	uint64_t loaded = _targets.size();
	Logger::log(LogLevel::Info,
		util::formatThousands(loaded) + " unique addresses loaded ("
		+ util::formatThousands(loadedP2PKH) + " P2PKH + "
		+ util::formatThousands(loadedP2WPKH) + " P2WPKH; "
		+ util::formatThousands(skipped) + " skipped/unsupported)");
	Logger::log(LogLevel::Info,
		"Target table size: "
		+ util::format("%.1f", (double)(sizeof(KeySearchTarget) * loaded) / (double)(1024 * 1024))
		+ " MB host-side");

	if(loaded == 0) {
		throw KeySearchException(
			"No supported addresses found in '" + targetsFile
			+ "'. BitCrack matches P2PKH ('1...') and native P2WPKH ('bc1q...') only.");
	}

    _device->setTargets(_targets);
}


void KeyFinder::setResultCallback(void(*callback)(KeySearchResult))
{
	_resultCallback = callback;
}

void KeyFinder::setStatusCallback(void(*callback)(KeySearchStatus))
{
	_statusCallback = callback;
}

void KeyFinder::setStatusInterval(uint64_t interval)
{
	_statusInterval = interval;
}

void KeyFinder::setTargetsOnDevice()
{
	// Set the target in constant memory
	std::vector<struct hash160> targets;

	for(std::set<KeySearchTarget>::iterator i = _targets.begin(); i != _targets.end(); ++i) {
		targets.push_back(hash160((*i).value));
	}

    _device->setTargets(_targets);
}

void KeyFinder::init()
{
	Logger::log(LogLevel::Info, "Initializing " + _device->getDeviceName());

    _device->init(_startKey, _compression, _stride);
}


void KeyFinder::stop()
{
	_running = false;
}

void KeyFinder::removeTargetFromList(const unsigned int hash[5])
{
	KeySearchTarget t(hash);

	_targets.erase(t);
}

bool KeyFinder::isTargetInList(const unsigned int hash[5])
{
	KeySearchTarget t(hash);
	return _targets.find(t) != _targets.end();
}


void KeyFinder::run()
{
    uint64_t pointsPerIteration = _device->keysPerStep();

	_running = true;

	util::Timer timer;

	timer.start();

	uint64_t prevIterCount = 0;

	_totalTime = 0;

	while(_running) {

        _device->doStep();
        _iterCount++;

		// Update status
		uint64_t t = timer.getTime();

		if(t >= _statusInterval) {

			KeySearchStatus info;

			uint64_t count = (_iterCount - prevIterCount) * pointsPerIteration;

			_total += count;

			double seconds = (double)t / 1000.0;

			info.speed = (double)((double)count / seconds) / 1000000.0;

			info.total = _total;

			info.totalTime = _totalTime;

			uint64_t freeMem = 0;

			uint64_t totalMem = 0;

			_device->getMemoryInfo(freeMem, totalMem);

			info.freeMemory = freeMem;
			info.deviceMemory = totalMem;
			info.deviceName = _device->getDeviceName();
			info.targets = _targets.size();
            info.nextKey = getNextKey();

			_statusCallback(info);

			timer.start();
			prevIterCount = _iterCount;
			_totalTime += t;
		}

        std::vector<KeySearchResult> results;

        if(_device->getResults(results) > 0) {

			for(unsigned int i = 0; i < results.size(); i++) {

				KeySearchResult info;
                info.privateKey = results[i].privateKey;
                info.publicKey = results[i].publicKey;
				info.compressed = results[i].compressed;
				info.address = Address::fromPublicKey(results[i].publicKey, results[i].compressed);

				_resultCallback(info);
			}

			// Remove the hashes that were found
			for(unsigned int i = 0; i < results.size(); i++) {
				removeTargetFromList(results[i].hash);
			}
		}

        // Stop if there are no keys left
        if(_targets.size() == 0) {
            Logger::log(LogLevel::Info, "No targets remaining");
            _running = false;
        }

		// Stop if we searched the entire range
        if(_device->getNextKey().cmp(_endKey) >= 0 || _device->getNextKey().cmp(_startKey) < 0) {
            Logger::log(LogLevel::Info, "Reached end of keyspace");
            _running = false;
        }
	}
}

secp256k1::uint256 KeyFinder::getNextKey()
{
    return _device->getNextKey();
}