#include "int-header.h"

namespace ns3 {

const uint64_t IntHop::lineRateValues[8] = {25000000000lu,50000000000lu,100000000000lu,200000000000lu,400000000000lu,0,0,0};
uint32_t IntHop::multi = 1;

IntHeader::Mode IntHeader::mode = NONE;
int IntHeader::pint_bytes = 2;

IntHeader::IntHeader() : nhop(0) {
	for (uint32_t i = 0; i < maxHop; i++)
		hop[i] = {0};
	dint_nhop = 0;
	dint_nsave = 0;
}

uint32_t IntHeader::GetStaticSize(){
	if (mode == NORMAL){
		return sizeof(hop) + sizeof(nhop);
	}else if (mode == TS){
		return sizeof(ts);
	}else if (mode == PINT){
		return sizeof(pint) + sizeof(dint_nhop) + sizeof(dint_nsave);
	}else {
		return 0;
	}
}

void IntHeader::PushHop(uint64_t time, uint64_t bytes, uint32_t qlen, uint64_t rate){
	// only do this in INT mode
	if (mode == NORMAL){
		uint32_t idx = nhop % maxHop;
		hop[idx].Set(time, bytes, qlen, rate);
		nhop++;
	}
}

void IntHeader::Serialize (Buffer::Iterator start) const{
	Buffer::Iterator i = start;
	if (mode == NORMAL){
		for (uint32_t j = 0; j < maxHop; j++){
			i.WriteU32(hop[j].buf[0]);
			i.WriteU32(hop[j].buf[1]);
		}
		i.WriteU16(nhop);
	}else if (mode == TS){
		i.WriteU64(ts);
	}else if (mode == PINT){
		if (pint_bytes == 1)
			i.WriteU8(pint.power_lo8);
		else if (pint_bytes == 2)
			i.WriteU16(pint.power);
		i.WriteU8(dint_nhop);
		i.WriteU8(dint_nsave);
	}
}

uint32_t IntHeader::Deserialize (Buffer::Iterator start){
	Buffer::Iterator i = start;
	if (mode == NORMAL){
		for (uint32_t j = 0; j < maxHop; j++){
			hop[j].buf[0] = i.ReadU32();
			hop[j].buf[1] = i.ReadU32();
		}
		nhop = i.ReadU16();
	}else if (mode == TS){
		ts = i.ReadU64();
	}else if (mode == PINT){
		if (pint_bytes == 1)
			pint.power_lo8 = i.ReadU8();
		else if (pint_bytes == 2)
			pint.power = i.ReadU16();
		dint_nhop = i.ReadU8();
		dint_nsave = i.ReadU8();
	}
	return GetStaticSize();
}

uint64_t IntHeader::GetTs(void){
	if (mode == TS)
		return ts;
	return 0;
}

uint16_t IntHeader::GetPower(void){
	if (mode == PINT)
		return pint_bytes == 1 ? pint.power_lo8 : pint.power;
	return 0;
}
void IntHeader::SetPower(uint16_t power){
	if (mode == PINT){
		if (pint_bytes == 1)
			pint.power_lo8 = power;
		else
			pint.power = power;
	}
}

uint8_t IntHeader::GetDintNhop() {
	return dint_nhop;
}

void IntHeader::SetDintNhop() {
	dint_nhop += 1;
}

uint8_t IntHeader::GetDintNsave() {
	return dint_nsave;
}

void IntHeader::SetDintNsave() {
	dint_nsave += 1;
}


// INT Header Wrap

NS_OBJECT_ENSURE_REGISTERED (IntHeaderWrap);

IntHeaderWrap::IntHeaderWrap ()
{
}

IntHeaderWrap::~IntHeaderWrap ()
{
}

TypeId
IntHeaderWrap::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::IntHeaderWrap")
    .SetParent<Header> ()
    .AddConstructor<IntHeaderWrap> ()
  ;
  return tid;
}

TypeId
IntHeaderWrap::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void 
IntHeaderWrap::Print (std::ostream &os) const
{
}

uint32_t
IntHeaderWrap::GetSerializedSize (void) const
{
	return GetStaticSize();
}
uint32_t IntHeaderWrap::GetStaticSize (void){
	return IntHeader::GetStaticSize();
}

void
IntHeaderWrap::Serialize (Buffer::Iterator start) const
{
	ih.Serialize(start);
}

uint32_t
IntHeaderWrap::Deserialize (Buffer::Iterator start)
{
	return ih.Deserialize(start);
}


}
