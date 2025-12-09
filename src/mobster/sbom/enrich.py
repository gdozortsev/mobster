from datetime import datetime
from abc import ABC, abstractmethod
from pathlib import Path
import json, os
from typing import Any, Sequence

import mobster.sbom.merge as merge 
from mobster.sbom.merge import CDXComponent, SPDXPackage

class SBOMEnricher(ABC):
    
    @abstractmethod 
    def enrich(
        self,
        target_sbom: dict[str, Any],
        incoming_sbom: dict[str, Any],
    ) -> dict[str, Any]:  # pragma: no cover
        """
        Enrich two SBOMs.
        This method should be implemented by subclasses.
        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom
        Returns:
            dict[str, Any]: The enriched SBOM
        """
        raise NotImplementedError("Enrich method logic is implemented in subclasses.")
    

class CycloneDXEnricher(SBOMEnricher):  # pylint: disable=too-few-public-methods
    """
    Enrich class for CycloneDX SBOMs.
    """

    def enrich(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich a CycloneDX SBOM with an SBOM of any type

        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom

        Returns:
            dict[str, Any]: The enriched SBOM
        """
        if merge._detect_sbom_type(incoming_sbom) == "cyclonedx":
            return self.enrich_from_same_type(target_sbom, incoming_sbom)
        
        return self.enrich_from_different_type(target_sbom, incoming_sbom)
    
    def enrich_from_same_type(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError("TODO: implement this")

    def enrich_from_different_type(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError("TODO: implement this")
        
    
class SPDXEnricher(SBOMEnricher):  # pylint: disable=too-few-public-methods
    """
    Enrich class for SPDX SBOMs.
    """

    def enrich(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich a SPDX SBOM with an SBOM of any type

        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom

        Returns:
            dict[str, Any]: The enriched SBOM
        """
        target_packages = merge.wrap_as_spdx(target_sbom.get("packages", []))
        if merge._detect_sbom_type(incoming_sbom) == "cyclonedx":
            target_sbom["creationInfo"] = self.addToTools(target_sbom["creationInfo"], incoming_sbom["metadata"]["tools"])
            target_sbom["packages"] = self.enrich_from_different_type(target_packages, merge.wrap_as_cdx(incoming_sbom.get("components", [])))
            return target_sbom
        
        return self.enrich_from_same_type(target_sbom, incoming_sbom) 
    
    def enrich_from_same_type(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError("TODO: implement this")

    #NOTE: this is the target for the use case: Enrich SPDX SBOM produced by llm_compress with the OWASP CycloneDX AIBOM
    def enrich_from_different_type(self, target_packages: Sequence[SPDXPackage], incoming_components: Sequence[CDXComponent]):
        new_packages = []
        for component in incoming_components:
            component_purl = component.purl()
            for package in target_packages:
                    for purl in package.all_purls():
                        #ignore version, just need the URL
                        #assumes that there is a matching purl made by hermeto
                        if component_purl.type == purl.type and component_purl.namespace == purl.namespace and component_purl.name == purl.name:
                            package = self.enrichPackage(package.unwrap(), component.unwrap())
                    new_packages.append(package.unwrap())
        return new_packages
    
    def addToTools(self, creationInfo: dict[str,Any], tools: dict[str,Any]):
        for component in tools["components"]:
            creationInfo["creators"].append(f"Tool: {component["name"]}")
        return creationInfo
    def enrichPackage(self, package: dict[str,Any], component: dict[str,Any]):
        
        if "modelCard" in component:
            modelCard = component["modelCard"]
            annotations = []
            
            for field in modelCard['properties']:
                fieldName, fieldValue = field['name'], field['value']

                #bomFormat doesn't go in SPDX and serialNumber gets rebuilt as the SPDX id
                #specversion doesn't matter because we're using the SPDX version of the original
                prefer_original = ['bomformat', 'serialNumber', 'specVersion', 'external_references']
                if fieldName in prefer_original:
                    continue

                #TODO: fix this path!!
                spdxFieldName = self.getFieldName("src/mobster/sbom/SPDXmappings2.3.json", fieldName)
                #don't overwrite the field if its in the original SBOM, but add it in if its not
                if spdxFieldName and not (fieldName in package):
                    package[spdxFieldName] = fieldValue 
                    continue 


                spdxAIFieldName = self.getFieldName("src/mobster/sbom/SPDXmappingAI.json", fieldName)
                if spdxAIFieldName:   
                    self.makeAnnotationFromField(spdxAIFieldName, fieldValue) 
                    annotations.append(self.makeAnnotationFromField(spdxAIFieldName, fieldValue))
                    continue 

                print(f"The field {fieldName} does not correspond to any SPDX field or AI field. Skipping over field {field}")

            package["annotations"].extend(annotations)

        #TODO: should this look in something else besides modelCard? like metadata?
        return SPDXPackage(package)
        
    
    def makeAnnotationFromField(self, field, value):
        annotation = {"annotationDate": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "annotationType" : "OTHER",
                      "annotator": "Tool: OWASP AIBOM Generator",
                      "comment" : f"{field} : {value}"}
        return annotation 
    
    def getFieldName(self, file_path, fieldName):
        try:
            with open(file_path, 'r') as f:
                mappings = json.load(f)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            raise e
        if fieldName in mappings:
            return  mappings[fieldName]['SPDX_Equivalent']
        return None




def _create_enricher(
    target_sbom: dict[str, Any]
) -> SBOMEnricher:
    """
    Creates a merger for the given SBOMs.
    """
    target_type = merge._detect_sbom_type(target_sbom)

    if target_type == "cyclonedx":
        return CycloneDXEnricher()

    return SPDXEnricher() 

async def enrich_sbom(
    target_sbom: Path, incoming_sbom: Path | None = None
) -> dict[str, Any]:
    """
    Merge multiple SBOMs.

    This is the main entrypoint function for merging SBOMs.
    Currently supports merging multiple Syft SBOMs with up to
    1 Hermeto SBOM.

    Args:
        syft_sbom_paths: List of paths to Syft SBOMs
        hermeto_sbom_path: Optional path to Hermeto SBOM

    Returns:
        The merged SBOM

    Raises:
        ValueError: If there are not enough SBOMs to merge (at least
        one Syft SBOM with Hermeto SBOM, or multiple Syft SBOMs)
    """

    if not target_sbom or not incoming_sbom:
        raise ValueError("A target SBOM path and an incoming SBOM is required to enrich an SBOM.")
    
    target_sbom_loaded = await merge.load_sbom_from_json(target_sbom)
    incoming_sbom_loaded = await merge.load_sbom_from_json(incoming_sbom)
    #we only need the type of the target SBOM to create the enricher
    enricher = _create_enricher(target_sbom_loaded)
    return enricher.enrich(target_sbom_loaded, incoming_sbom_loaded)