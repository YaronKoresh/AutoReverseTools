/**
 * @file include/retdec/cpdetect/heuristics/pe_heuristics.h
 * @brief Definition of PeHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_HEURISTICS_PE_HEURISTICS_H
#define RETDEC_CPDETECT_HEURISTICS_PE_HEURISTICS_H

#include "retdec/cpdetect/heuristics/heuristics.h"
#include "retdec/fileformat/file_format/pe/pe_format.h"

namespace retdec {
namespace cpdetect {

struct PeHeaderStyle
{
	// Note: Having "(const) std::string" instead of "const char *" here
	// makes MS Visual Studio 2017 compiler (v 15.9.8) exit with
	// "fatal error C1001: An internal error has occurred in the compiler"
	// const std::string headerStyle;
	const char * headerStyle;
	uint16_t headerWords[0x0D];
};

/**
 * PE-specific heuristics
 */
class PeHeuristics : public Heuristics
{
	private:
		retdec::fileformat::PeFormat &peParser; ///< parser of input PE file

		std::size_t declaredLength; ///< declared length of file
		std::size_t loadedLength;   ///< actual loaded length of file

		/// @name Auxiliary methods
		/// @{
		std::string getEnigmaVersion();
		std::string getUpxAdditionalInfo(std::size_t metadataPos);
		/// @}

		/// @name Heuristics for detection of original language
		/// @{
		void getGoHeuristics();
		void getAutoItHeuristics();
		void getDotNetHeuristics();
		void getVisualBasicHeuristics();
		/// @}

		/// @name Heuristics for detection of used compiler or packer
		/// @{
		std::int32_t getInt32Unaligned(const std::uint8_t * codePtr);
		const std::uint8_t * skip_NOP_JMP8_JMP32(
				const std::uint8_t * codeBegin,
				const std::uint8_t * codePtr,
				const std::uint8_t * codeEnd,
				std::size_t maxCount);
		void getHeaderStyleHeuristics();
		void getSlashedSignatures();
		void getMorphineHeuristics();
		void getStarForceHeuristics();
		void getSafeDiscHeuristics();
		bool checkSecuROMSignature(
				const char * fileData,
				const char * fileDataEnd,
				uint32_t FileOffset);
		void getSecuROMHeuristics();
		void getMPRMMGVAHeuristics();
		void getActiveMarkHeuristics();
		void getRLPackHeuristics();
		void getPetiteHeuristics();
		void getPelockHeuristics();
		void getEzirizReactorHeuristics();
		void getUpxHeuristics();
		void getFsgHeuristics();
		void getPeCompactHeuristics();
		void getAndpakkHeuristics();
		void getEnigmaHeuristics();
		void getVBoxHeuristics();
		void getActiveDeliveryHeuristics();
		void getAdeptProtectorHeuristics();
		void getCodeLockHeuristics();
		void getNetHeuristic();
		void getExcelsiorHeuristics();
		void getVmProtectHeuristics();
		void getBorlandDelphiHeuristics();
		void getBeRoHeuristics();
		void getMsvcIntelHeuristics();
		void getArmadilloHeuristic();
		void getStarforceHeuristic();
		void getLinkerVersionHeuristic();
		void getRdataHeuristic();
		void getNullsoftHeuristic();
		void getManifestHeuristic();
		void getSevenZipHeuristics();
		void getMewSectionHeuristics();
		void getNsPackSectionHeuristics();
		void getPeSectionHeuristics();
		/// @}

	protected:
		/// @name Virtual methods
		/// @{
		virtual void getFormatSpecificCompilerHeuristics() override;
		virtual void getFormatSpecificLanguageHeuristics() override;
		/// @}

	public:
		PeHeuristics(
				retdec::fileformat::PeFormat &parser, Search &searcher,
				ToolInformation &toolInfo);
};

} // namespace cpdetect
} // namespace retdec

#endif
