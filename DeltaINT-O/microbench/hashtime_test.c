#include <vector>
#include <random>

#include "hash.h"
#include "helper.h"

int main(int argc, char **argv) {
	// NOTE: rd() generates a random seed
	//std::random_device rd;
	//std::mt19937 gen(rd());
	std::mt19937 gen(0);
	std::uniform_int_distribution<int> dist(0, 255);

	int loopcnt = 1000 * 1000;
	int flowkey_len = 13;

	// initialize random flowkeys
	uint8_t **flowkeys = new uint8_t*[loopcnt];
	for (int i = 0; i < loopcnt; i++) {
		flowkeys[i] = new uint8_t[flowkey_len];
	}

	// randomly generate flowkeys
	for (int i = 0; i < loopcnt; i++) {
		for (int j = 0; j < flowkey_len; j++) {
			flowkeys[i][j] = dist(gen);
		}
	}

	// test mmh3
	struct timespec mmh3_t1, mmh3_t2, mmh3_t3;
	CUR_TIME(mmh3_t1);
	for (int i = 0; i < loopcnt; i++) {
		mmh3(flowkeys[i], flowkey_len, i);
	}
	CUR_TIME(mmh3_t2);
	DELTA_TIME(mmh3_t2, mmh3_t1, mmh3_t3);
	double mmh3_totaltime = GET_MICROSECOND(mmh3_t3);
	printf("mmh3 avg hash time: %f us\n", mmh3_totaltime / loopcnt);

	// test ecmphash
	struct timespec ecmphash_t1, ecmphash_t2, ecmphash_t3;
	CUR_TIME(ecmphash_t1);
	for (int i = 0; i < loopcnt; i++) {
		EcmpHash(flowkeys[i], flowkey_len, i);
	}
	CUR_TIME(ecmphash_t2);
	DELTA_TIME(ecmphash_t2, ecmphash_t1, ecmphash_t3);
	double ecmphash_totaltime = GET_MICROSECOND(ecmphash_t3);
	printf("ecmphash avg hash time: %f us\n", ecmphash_totaltime / loopcnt);

	// free generated flowkeys
	for (int i = 0; i < loopcnt; i++) {
		delete [] flowkeys[i];
		flowkeys[i] = NULL;
	}
	delete [] flowkeys;
	flowkeys = NULL;
}
