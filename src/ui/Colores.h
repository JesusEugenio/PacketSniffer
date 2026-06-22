//
// Created by aranz on 20/06/2026.
//

#ifndef COLORES_H
#define COLORES_H
#include "imgui.h"

namespace Colores {
	//Paleta de colores
	inline const ImU32 BLANCO= 0xFFFFFFFF;
	inline const ImU32 NEGRO= 0xFF000000;

	inline const ImU32 CREMA= 0xFFD1D4DB;
	inline const ImU32 CREMAPASTEL= 0xFFCED6DF;
	inline const ImU32 CREMACLARO= 0xFFE3E7EC;
	inline const ImU32 AZULGRISACEOOSCURO= 0xFF9E7971;
	inline const ImU32 AZULGRISACEO= 0xFFC8AF8C;
	inline const ImU32 AZULPASTEL= 0xFFD7C4A9;
	inline const ImU32 VERDEMENTAGRISACEO= 0xFFC7C5BA;
	inline const ImU32 GRISVERDIOSOCLARO= 0xFFCCDCDC;
	inline const ImU32 MORADOGRISACEOCAFE= 0xFFC8BFC2;
	inline const ImU32 MORADOGRISACEO= 0xFFBEAAA8;
	inline const ImU32 CAFEMORADOSO= 0xFFB7ACB6;
	inline const ImU32 ROSAVIEJO= 0xFFB0ADC3;
	inline const ImU32 MORADOVIEJO= 0xFFC7B3C0;
	inline const ImU32 AZULMARINOOSCURO = 0xFF634F3A;
	inline const ImU32 ROSAVIEJOOSCURO= 0xFF6D5790;
	inline const ImU32 ROSATENUE= 0xFFE5CAEF;

	//colores de atributos exactos
	inline const ImU32 INPUT = AZULPASTEL;
    inline const ImU32 TEXTINPUT = NEGRO;
    inline const ImU32 TOOLBAR = AZULPASTEL;
    inline const ImU32 BOTONESGENERAL = ROSAVIEJO;
	inline const ImU32 VENTANA = CREMA;
	inline const ImU32 BOTONESGENERALPRESS = MORADOVIEJO;
	inline const ImU32 BOTONESGENERALHOVER = ROSAVIEJOOSCURO;
	inline const ImU32 DEFAULTETIQUETA = ROSAVIEJOOSCURO;

}
#endif //COLORES_H
