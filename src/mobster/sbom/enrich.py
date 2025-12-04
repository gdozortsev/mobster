from datetime import datetime
from abc import ABC, abstractmethod
import os
from pathlib import Path
from urllib.parse import urlparse
import json
from typing import Any

from packageurl import PackageURL

import mobster.sbom.merge as merge 

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
        if merge._detect_sbom_type(incoming_sbom) == "cyclonedx":
            return self.enrich_from_different_type(target_sbom, incoming_sbom)
        
        return self.enrich_from_same_type(target_sbom, incoming_sbom) 

    def enrich_from_same_type(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError("TODO: implement this")

    #NOTE: this is the target for the use case: Enrich SPDX SBOM produced by llm_compress with the OWASP CycloneDX AIBOM
    def enrich_from_different_type(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:

        tools = self.getToolNames(incoming_sbom)
        for tool in tools:
            target_sbom["creationInfo"]["creators"].append(f"Tool: {tool}")
        new_package = self.make_SPDXPackage_from_CDXComponent(incoming_sbom)
        target_sbom["packages"].append(new_package[0])
        return target_sbom
    
    def make_SPDXPackage_from_CDXComponent(self, sbom: dict[str, Any]) -> dict[str, Any]:
        components = merge.wrap_as_cdx(sbom.get("components", []))

        packages = []
        for component in components:
            if component.data['modelCard']:
                rebuiltModelCard = self.extractFromModelCard(component.data['modelCard'])
                rebuiltModelCard = {"SPDXID": self.SPDX_to_CDX_id(component.purl()), **rebuiltModelCard}
                packages.append(rebuiltModelCard)
        return packages


    def extractFromModelCard(self, modelCard: dict[str, Any]) -> dict[str, Any]:
        
        rebuiltModelCard = {}
        annotations = []
        for field in modelCard['properties']:
            fieldName, fieldValue = field['name'], field['value']

            #bomFormat doesn't go in SPDX and serialNumber gets rebuilt as the SPDX id
            #specversion doesn't matter because we're using the SPDX version of the original
            if fieldName == 'bomFormat' or fieldName =='serialNumber' or fieldName == 'specVersion':
                continue

            if fieldName == 'external_references':
                rebuiltModelCard["externalRefs"] = self.transformExternalRefs(fieldValue)
                continue


            #TODO: fix this path!!

            print("IS IT HEREEE: ", os.getcwd())
            spdxFieldName = self.getFieldName("SPDXmappings2.3.json", fieldName)
            if spdxFieldName:
                rebuiltModelCard[spdxFieldName] = fieldValue 
                continue 


            spdxAIFieldName = self.getFieldName("SPDXmappingAI.json", fieldName)
            if spdxAIFieldName:   
                self.makeAnnotationFromField(spdxAIFieldName, fieldValue) 
                annotations.append(self.makeAnnotationFromField(spdxAIFieldName, fieldValue))

        rebuiltModelCard["annotations"] = annotations
        return rebuiltModelCard
    
    def getToolNames(self, sbom: dict[str, Any]):
        tools = []
        components = sbom["metadata"]["tools"]["components"]
        if len(components) > 0:
             for comp in components:
                tools.append(comp["name"])
        return tools
    
    def transformExternalRefs(self, refs_string):
        try:
            external_refs_list = json.loads(refs_string)
        except json.JSONDecodeError:
            return []

        transformed_refs_list = []
        for ref in external_refs_list:
            parsed_url = urlparse(ref["url"])
            namespace = parsed_url.netloc.split(".")[0]
            path = parsed_url.path.strip('/')
            transformed_refs_list.append({
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceLocator": f"pkg:{namespace}/{path}",
                    "referenceType": "purl"
                })
        return transformed_refs_list

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
    
    def SPDX_to_CDX_id(self, purl: PackageURL):
        package_name = purl.name

        #extract the namespace
        namespace_parts = purl.namespace.split('/') if purl.namespace else []
        
        if namespace_parts:
            namespace_identifier = namespace_parts[0]
        else:
            namespace_identifier = ""

        if namespace_identifier:
            identifier_base = f"{namespace_identifier}-{package_name}"
        else:
            identifier_base = package_name

        spdx_id = f"SPDXRef-Package-{identifier_base}"
        spdx_id = spdx_id.replace('/', '-') 
        
        return spdx_id
    


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