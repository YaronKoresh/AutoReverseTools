/**
 * @file include/retdec/cpdetect/heuristics/macho_heuristics.h
 * @brief Definition of MachOHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_HEURISTICS_MACHO_HEURISTICS_H
#define RETDEC_CPDETECT_HEURISTICS_MACHO_HEURISTICS_H

#include "retdec/cpdetect/heuristics/heuristics.h"
#include "retdec/fileformat/file_format/macho/macho_format.h"

namespace retdec {
namespace cpdetect {

/**
 * Mach-O-specific heuristics
 */
class MachOHeuristics : public Heuristics
{
	private:
		/// @name Detection methods
		/// @{
		void getUpxHeuristic();
		void getGoHeuristic();
		void getSectionTableHeuristic();
		void getImportTableHeuristic();
		/// @}

	protected:
		/// @name Virtual methods
		/// @{
		virtual void getFormatSpecificCompilerHeuristics() override;
		/// @}

	public:
		MachOHeuristics(
				retdec::fileformat::MachOFormat &parser,
				Search &searcher,
				ToolInformation &toolInfo);
};

} // namespace cpdetect
} // namespace retdec

#endif
