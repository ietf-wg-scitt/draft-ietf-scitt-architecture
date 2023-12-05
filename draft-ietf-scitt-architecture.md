---
v: 3

title: An Architecture for Trustworthy and Transparent Digital Supply Chains
abbrev: SCITT Architecture
docname: draft-ietf-scitt-architecture-latest

area: Security
wg: SCITT
kw: Internet-Draft
cat: std
consensus: yes
submissiontype: IETF

kramdown_options:
  auto_id_prefix: sec-

author:
- name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- name: Antoine Delignat-Lavaud
  organization: Microsoft Research
  street: 21 Station Road
  code: 'CB1 2FB'
  city: Cambridge
  email: antdl@microsoft.com
  country: UK
- name: Cedric Fournet
  organization: Microsoft Research
  street: 21 Station Road
  code: 'CB1 2FB'
  city: Cambridge
  email: fournet@microsoft.com
  country: UK
- name: Yogesh Deshpande
  organization: ARM
  street: 110 Fulbourn Road
  code: 'CB1 9NJ'
  city: Cambridge
  email: yogesh.deshpande@arm.com
  country: UK
- ins: S. Lasker
  name: Steve Lasker
  org: DataTrails
  email: steve.lasker@datatrails.ai
  city: Seattle
  country: United States

contributor:
  - ins: O. Steele
    name: Orie Steele
    organization: Transmute
    email: orie@transmute.industries
    country: United States
    contribution: >
      Orie contributed to improving the generalization of COSE building blocks and document consistency.

normative:
  RFC8610: CDDL
  RFC9052: COSE
  RFC8949: CBOR
#  RFC9053: COSE-ALGS
#  RFC9054: COSE-HASH
  RFC9457:
  RFC9110:
  RFC6838:
  RFC3553:
  RFC9360:
  IANA.params:
  IANA.cose:
  COSWID:
    target: https://www.rfc-editor.org/rfc/rfc9393
    title:  COSWID Specification
  CWT_CLAIM_COSE:
    target: https://datatracker.ietf.org/doc/draft-ietf-cose-cwt-claims-in-headers/
    title: CBOR Web Token (CWT) Claims in COSE Headers
  I-D.draft-birkholz-scitt-scrapi: scrapi

informative:
  I-D.draft-steele-cose-merkle-tree-proofs: COMETRE
  PBFT: DOI.10.1145/571637.571640
  MERKLE: DOI.10.1007/3-540-48184-2_32
  RFC6024:
  RFC9162: CT
  RFC9334: rats-arch
  I-D.ietf-scitt-software-use-cases:
  CWT_CLAIMS:
    target: https://www.iana.org/assignments/cwt/cwt.xhtml
    title: CBOR Web Token (CWT) Claims
  CycloneDX:
    target: https://cyclonedx.org/specification/overview/
    title:  CycloneDX
  in-toto:
    target: https://in-toto.io/
    title:  in-toto
  SLSA:
    target: https://slsa.dev/
    title:  SLSA
  SPDX-JSON:
    target: https://spdx.dev/use/specifications/
    title:  SPDX Specification
  SPDX-CBOR:
    target: https://spdx.dev/use/specifications/
    title:  SPDX Specification
  SWID:
    target: https://csrc.nist.gov/Projects/Software-Identification-SWID/guidelines
    title:  SWID Specification
  EQUIVOCATION: DOI.10.1145/1323293.1294280

venue:
  mail: scitt@ietf.org
  github: ietf-wg-scitt/draft-ietf-scitt-architecture

--- abstract

Traceability of physical and digital Artifacts in supply chains is a long-standing, but increasingly serious security concern.
The rise in popularity of verifiable data structures as a mechanism to make actors more accountable for breaching their compliance promises has found some successful applications to specific use cases (such as the supply chain for digital certificates), but lacks a generic and scalable architecture that can address a wider range of use cases.

This document defines a generic, interoperable and scalable architecture to enable transparency across any supply chain with minimum adoption barriers.
It provides flexibility, enabling interoperability across different implementations of Transparency Services with various auditing and compliance requirements.
Issuers can register their Signed Statements on any Transparency Service, with the guarantee that all Consumers will be able to verify them.

Within the SCITT Architecture, a producer is known as an Issuer, and a consumer is known as a Verifier.

--- middle

# Introduction

This document describes a scalable and flexible, decentralized architecture to enhance auditability and accountability across various existing and emerging supply chains.
It achieves this goal by enforcing the following complementary security guarantees:

1. Statements made by Issuers about supply chain Artifacts must be identifiable, authentic, and non-repudiable
1. Such Statements must be registered on a secure Append-only Log, enabling provenance and history to be independently and consistently audited
1. Issuers can efficiently prove to any other party the Registration of their Signed Statements; verifying this proof ensures that the Issuer is consistent and non-equivocal when producing Signed Statements

The first guarantee is achieved by requiring Issuers to sign their Statements and associated metadata using a distributed public key infrastructure.
The second guarantee is achieved by storing the Signed Statement on an immutable, Append-only Log.
The next guarantee is achieved by implementing the Append-only Log using a verifiable data structure (such as a Merkle Tree {{MERKLE}}).
Lastly, the Transparency Service verifies the identity of the Issuer, and conformance to a Registration Policy associated with the instance of the Transparency Service.
As the Issuer of the Signed Statement and conformance to the Registration Policy are confirmed, an endorsement is made as the Signed Statement is added to the Append-only Log.

The guarantees and techniques used in this document generalize those of Certificate Transparency {{-CT}}, which can be re-interpreted as an instance of this architecture for the supply chain of X.509 certificates.
However, the range of use cases and applications in this document is broader, which requires more flexibility in how each Transparency Service is implemented and operates.

Each service MAY enforce its own Registration Policies for authorizing entities to register their Signed Statements to the Append-only Log.
Some Transparency Services may also enforce authorization policies limiting who can write, read and audit the Append-only Log.
It is critical to provide interoperability for all Transparency Services instances as the composition of supply chain entities is ever-changing.
It is implausible to expect all participants to choose a single vendor or Append-only Log.

A Transparency Service provides visibility into Signed Statements associated with various supply chains and their sub-systems.
The Signed Statements (and inner payload) make claims about the Artifacts produced by a supply chain.
A Transparency Service endorses specific and well-defined metadata about Artifacts which are captured in the envelope of the Statements.
Some metadata is selected (and signed) by the Issuer ("who issued the Statement", "what type of Artifact is described", "what is the Artifact's version").
Whereas additional metadata is selected (and countersigned) by the Transparency Services ("when was the Signed Statement about an Artifact registered in the Transparency Service", "which registration policy was used").
Evaluating and Registering a Signed Statement, adding it to the Append-only Log, and producing a Transparent Statement is considered a form of counter-signed notarization.

A Statements payload content is always opaque and MAY be encrypted when submitted to the Transparency Services.
However the header metadata MUST be transparent in order to warrant trust for later processing.

Transparent Statements provide a common basis for holding Issuers accountable for the Statement payload about Artifacts they release.
Multiple Issuers may Register additional Signed Statements about the same Artifact, but they cannot delete or alter Signed Statements previously added to the Append-only Log.
The ability for the original Issuer to make additional Statements about an Artifact provides for updated information to be shared, such as new positive or negative validations of quality.
The ability of other Issuers to make Statements about an Artifact, produced from another Issuer, provides for third party validations.
A Transparency Service may restrict access to Signed Statements through access control or Registration policies.
However, third parties (such as Auditors) would be granted access as needed to attest to the validity of the Artifact, Subject or the entirety of the Transparency Service.
Independent third parties may also make Statements about an Artifact, published on other Transparency Services.

Trust in the Transparency Service itself is supported both by protecting their implementation (using replication, trusted hardware, and remote attestation of a system's operational state) and by enabling independent audits of the correctness and consistency of its Append-only Log, thereby holding the organization that operates it accountable.
Unlike CT, where independent Auditors are responsible for enforcing the consistency of multiple independent instances of the same global Transparency Service, each Transparency Service is required to guarantee the consistency of its own Append-only Log (through the use of a consensus algorithm between replicas of the Transparency Service), but assume no consistency between different Transparency Services.

Breadth of verifier access is critical.
As a result, the Transparency Service specified in this architecture caters to two types of audiences:

1. **Issuers**: organizations, stakeholders, and users involved in creating or attesting to supply chain artifacts, releasing authentic Statements to a definable set of peers
1. **Verifiers**: organizations, stakeholders, consumers, and users involved in validating supply chain artifacts, but can only do so if the Statements are known to be authentic.
Verifiers MAY be Issuers, providing additional Signed Statements, attesting to conformance of various compliance requirements.

The Issuer of a Signed Statement must be authenticated and authorized according to the Registration Policy of the Transparency Service.
Analogously, Transparent Statement Verifiers rely on verifiable trustworthiness assertions associated with Transparent Statements and their processing provenance in a believable manner.
If trust can be put into the operations that record Signed Statements in a secure, Append-only Log via online operations, the same trust can be put into the resulting Transparent Statement, issued by the Transparency Services and that can be validated in offline operations.

The Transparency Services specified in this architecture are language independent and can be implemented alongside or within existing services.

The interoperability guaranteed by the Transparency Services is enabled via core components (architectural constituents).
Many of the data elements processed by the core components are based on the CBOR Signing and Encryption (COSE) standard specified in {{-COSE}}, which is used to produce Signed Statements about Artifacts and to build and maintain an Append-only Log for corresponding Signed Statements.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Use Cases

The building blocks defined in SCITT are intended to support applications in any supply chain that produces or relies upon digital artifacts, from the build and supply of software and IoT devices to advanced manufacturing and food supply.

Detailed use cases are maintained in a separate document {{I-D.ietf-scitt-software-use-cases}}.

# Terminology {#terminology}

The terms defined in this section have special meaning in the context of Supply Chain Integrity, Transparency, and Trust, which are used throughout this document.
When used in text, the corresponding terms are capitalized.
To ensure readability, only a core set of terms is included in this section.

Append-only Log (converges Ledger and Registry):

: the verifiable append-only data structure that stores Signed Statements in a Transparency Service often referred to by the synonym, Registry, Log or Ledger.
SCITT supports multiple Log and Receipt formats to accommodate different Transparency Service implementations, and the proof types associated with different types of Append-only Log.

Artifact:

: a physical or non-physical item that is moving along a supply chain.

Auditor:

: an entity that checks the correctness and consistency of all Transparent Statements issued by a Transparency Service.

Envelope:

: metadata, created by the Issuer to produce a Signed Statement.
The Envelope contains the identity of the Issuer and information about the Artifact, enabling Transparency Service Registration Policies to validate the Signed Statement.
A Signed Statement is a COSE Envelope wrapped around a Statement, binding the metadata in the Envelope to the Statement.
In COSE, an Envelope consists of a protected header (included in the Issuer's signature) and an unprotected header (not included in the Issuer's signature).

Equivocation:

: a state where it is possible for a Transparency Service to provide different views of its append-only log to Verifiers about the same Artifact {{EQUIVOCATION}}.

Feed:

: see Subject

Issuer:

: organizations, stakeholders, and users involved in creating or attesting to supply chain artifacts, releasing authentic Statements to a definable set of peers.
An Issuer may be the owner or author of Artifacts, or an independent third party such as an auditor, reviewer or an endorser.

Non-equivocation:

: a state where it is impossible for a Transparency Service to provide different views of its append-only log to Verifiers about the same Artifact.
Over time, an Issuer may register new Signed Statements about an Artifact in a Transparency Service with new information. However, the consistency of a collection of Signed Statements about the Artifact can be checked by all Verifiers.

Receipt:

: a Receipt is a cryptographic proof that a Signed Statement is recorded in the Append-only Log.
Receipts are based on Signed Inclusion Proofs as described in COSE Signed Merkle Tree Proofs {{-COMETRE}}.
Receipts can be built on different verifiable data structures, not just binary merkle trees.
Receipts consist of Transparency Service-specific inclusion proofs, a signature by the Transparency Service of the state of the Append-only Log, and additional metadata (contained in the signature's protected headers) to assist in auditing.

Registration:

: the process of submitting a Signed Statement to a Transparency Service, applying the Transparency Service's Registration Policy, adding to the Append-only Log, and producing a Receipt.

Registration Policy:

: the pre-condition enforced by the Transparency Service before registering a Signed Statement, based on information in the non-opaque header and metadata contained in its COSE Envelope.
A Transparency Service MAY implement any range of policies that meets their needs.
However a Transparency Service can not alter the contents of the Signed Statements.

Registry:

: See Append-only Log

Signed Statement:

: an identifiable and non-repudiable Statement about an Artifact signed by an Issuer.
In SCITT, Signed Statements are encoded as COSE signed objects; the payload of the COSE structure contains the issued Statement.

Statement:

: any serializable information about an Artifact.
To help interpretation of Statements, they must be tagged with a media type (as specified in {{RFC6838}}).
A Statement may represent a Software Bill Of Materials (SBOM) that lists the ingredients of a software Artifact, an endorsement or attestation about an Artifact, indicate the End of Life (EOL), redirection to a newer version,  or any content an Issuer wishes to publish about an Artifact.
The additional Statements about an artifact are correlated by the Subject defined in the CWT_Claims protected header.
The Statement is considered opaque to Transparency Service, and MAY be encrypted.

Subject:

: (Previously named Feed) a logical collection of Statements about the same Artifact.
For any step or set of steps in a supply chain there may be multiple statements made about the same Artifact.
Issuers use Subject to create a coherent sequence of Signed Statements about the same Artifact and Verifiers use the Subject to ensure completeness and Non-equivocation in supply chain evidence by identifying all Transparent Statements linked to the one(s) they are evaluating.
In SCITT, Subject is a property of the dedicated, protected header attribute `15: CWT_Claims` within the protected header of the COSE envelope.

Transparency Service:

: an entity that maintains and extends the Append-only Log, and endorses its state.
A Transparency Service MAY implement a Registration Policy, often referred to by its synonym Notary.
A Transparency Service can be a complex distributed system, and SCITT requires the Transparency Service to provide many security guarantees about its Append-only Log.
The identity of a Transparency Service is captured by a public key that must be known by Verifiers in order to validate Receipts.

Transparent Statement:

: a Signed Statement that is augmented with a Receipt created via Registration in a Transparency Service.
The receipt is stored in the unprotected header of COSE Envelope of the Signed Statement.
A Transparent Statement remains a valid Signed Statement, and may be registered again in a different Transparency Service.

Verifier:

: organizations, stakeholders, and users involved in validating supply chain Artifacts.
Verifiers consume Transparent Statements, verifying their proofs and inspecting the Statement payload, either before using corresponding Artifacts, or later to audit an Artifact's provenance on the supply chain.

{: #mybody}

# Definition of Transparency

In this document, the definition of transparency is intended to build over abstract notions of Append-only Logs and Receipts.
Existing transparency systems such as Certificate Transparency are instances of this definition.

A Signed Statement is an identifiable and non-repudiable Statement made by an Issuer.
The Issuer selects additional metadata and attaches a proof of endorsement (in most cases, a signature) using the identity key of the Issuer that binds the Statement and its metadata.
Signed Statements can be made transparent by attaching a proof of Registration by a Transparency Service, in the form of a Receipt that countersigns the Signed Statement and witnesses its inclusion in the Append-only Log of a Transparency Service.
By extension, the document may say an Artifact (a firmware binary) is transparent if it comes with one or more Transparent Statements from its author or owner, though the context should make it clear what type of Signed Statements is expected for a given Artifact.

Transparency does not prevent dishonest or compromised Issuers, but it holds them accountable.
Any Artifact that may be verified, is subject to scrutiny and auditing by other parties.
The Transparency Service provides a history of Statements, which may be made by multiple Issuers, enabling Verifiers to make informed decisions.

Transparency is implemented by providing a consistent, append-only, cryptographically verifiable, publicly available record of entries.
A SCITT instance is referred to as a Transparency Service.
Implementations of Transparency Services may protect their Append-only Log using a combination of trusted hardware, replication and consensus protocols, and cryptographic evidence.
A Receipt is an offline, universally-verifiable proof that an entry is recorded in the Append-only Log.
Receipts do not expire, but it is possible to append new entries (more recent Signed Statements) that subsume older entries (less recent Signed Statements).

Anyone with access to the Transparency Service can independently verify its consistency and review the complete list of Transparent Statements registered by each Issuer.
However, the Registrations of separate Transparency Services are generally disjoint, though it is possible to take a Transparent Statement from one Transparency Service and register it again on another (if its policy allows), so the authorization of the Issuer and of the Transparency Service by the Verifier of the Receipt are generally independent.

Reputable Issuers are thus incentivized to carefully review their Statements before signing them to produce Signed Statements.
Similarly, reputable Transparency Services are incentivized to secure their Append-only Log, as any inconsistency can easily be pinpointed by any Auditor with read access to the Transparency Service.
Some Append-only Log formats may also support consistency auditing ({{sec-consistency}}) through Receipts, that is, given two valid Receipts the Transparency Service may be asked to produce a cryptographic proof that they are consistent.
Failure to produce this proof can indicate that the Transparency Services operator misbehaved.

# Architecture Overview

~~~aasvg
                 .----------.
                |  Artifact  |
                 '----+-----'
                      v
                 .----+----.  .----------.  Identifiers
Issuer      --> | Statement ||  Envelope  +<------------------.
                 '----+----'  '-----+----'                     |
                      |             |           +--------------+---+
                       '----. .----'            | Identity         |
                             |                  | Documents        |
                             v                  +-------+------+---+
                        .----+----.                     |      |
                       |  Signed   |    COSE Signing    |      |
                       | Statement +<-------------------+      |
                        '----+----'                     |      |
                             |               +----------+---+  |
                          .-' '------------->+ Transparency |  |
                         |   .-------.       |              |  |
Transparency -->         |  | Receipt +<-----+   Service    |  |
     Service             |   '---+---'       +------------+-+  |
                          '-. .-'                         |    |
                             |                            |    |
                             v                            |    |
                       .-----+-----.                      |    |
                      | Transparent |                     |    |
                      |  Statement  |                     |    |
                       '-----+-----'                      |    |
                             |                            |    |
                             |'-------.     .-------------)---'
                             |         |   |              |
                             |         v   v              |
                             |    .----+---+-----------.  |
Verifier     -->             |   / Verify Transparent /   |
                             |  /      Statement     /    |
                             | '--------------------'     |
                             v                            v
                    .--------+---------.      .-----------+-----.
Auditor      -->   / Collect Receipts /      /   Replay Log    /
                  '------------------'      '-----------------'
~~~

The SCITT architecture consists of a very loose federation of Transparency Services, and a set of common formats and protocols for issuing and registering Signed Statements, and auditing Transparent Statements.

In order to accommodate as many Transparency Service implementations as possible, this document only specifies the format of Signed Statements (which must be used by all Issuers) and a very thin wrapper format for Receipts, which specifies the Transparency Service identity and the agility parameters for the Signed Inclusion Proofs.
Most of the details of the Receipt's contents are specified in the COSE Signed Merkle Tree Proof document {{-COMETRE}}.

This section describes at a high level, the three main roles and associated processes in SCITT: Issuers and the Signed Statement issuance process, Transparency Service and the Signed Statement Registration process, as well as Verifiers of the Transparent Statements and the Receipt validation process.

## Signed Statement Issuance and Registration

### Issuer Identity

Before an Issuer is able to produce Signed Statements, it must first create an identifier and obtain an identity document, that is acceptable to the Transparency Service.
Transparency Services MAY support many different identity document formats.

Issuers SHOULD use consistent identifiers for all their Statements about Artifacts, to simplify authorization by Verifiers and auditing.
If an Issuer uses multiple identifiers, they MUST ensure that statements signed under each identifier are consistent.

Issuers MAY rotate verification keys at any time, or at a consistent cryptoperiod.
Issuers MAY migrate to new signing and verification algorithms, but the Transparency Service remains responsible for admitting signed statements that match its policies.

The Issuer's identifier is required and appears in the `1 iss` claim of the `15 CWT_Claims` protected header of the Signed Statements' Envelope.
The version of the key used to sign the Signed Statement is written in the `4 kid` protected header.

Key discovery protocols are out of scope for this document.

~~~ cddl
CWT_Claims = {
  1 => tstr; iss, the issuer making statements,
  2 => tstr; sub, the subject of the statements,
  * tstr => any
}

Protected_Header = {
  1   => int             ; algorithm identifier,
  4   => bstr            ; Key ID (kid),
  15  => CWT_Claims      ; CBOR Web Token Claims,
  393 => Reg_Info        ; Registration Policy info,
  3   => tstr            ; payload type
}
~~~

### Support for Multiple Artifacts

Issuers may produce Signed Statements about different Artifacts under the same Identity.
Issuers and Verifiers must be able to recognize the Artifact to which the statements pertain by looking at the Signed Statement.
The `iss` and `sub` claims, within the CWT_Claims protected header, are used to identify the Artifact the statement pertains to.

See Subject under {{terminology}} Terminology.

Issuers MAY use different signing keys (identified by `kid` in the resolved key manifest) for different Artifacts, or sign all Signed Statements under the same key.

### Registration Policy Metadata

SCITT payloads are opaque to Transparency Services.
For interoperability, Registration Policy decisions should be based on interpretation of information in the non-opaque Envelope.

The small mandatory set of metadata in the envelope of a Signed Statement is neither intended nor sufficient to express the information required for the processing of Registration Policies in a Transparency Service.

For example, a Transparency Service may only allow a Signed Statement to be registered if it was signed very recently, or may reject a Signed Statement if it arrives out of order in some sequenced protocol.

Any metadata meant to be interpreted by the Transparency Service during Registration Policy evaluation, SHOULD be added to the `reg_info` header, unless the data is private, in which case it MAY be sent to the Transparency Service as an additional input during registration.

While the `Reg_Info` header MUST be present in all Signed Statements, all attributes are optional, and the map MAY be empty.

## Transparency Service

The role of Transparency Service can be decomposed into several major functions.
The most important is maintaining an Append-only Log, the verifiable data structure that records Signed Statements, and enforcing a Registration Policy.
It also maintains a service key, which is used to endorse the state of the Append-only Log in Receipts.
All Transparency Services MUST expose standard endpoints for Registration of Signed Statements and Receipt issuance, which is described in {{-scrapi}}.
Each Transparency Service also defines its own Registration Policies, which MUST apply to all entries in the Append-only Log.

The combination of Identity, Registration Policy evaluation, and the Transparency Service endpoint constitute the trusted part of the Transparency Service.
Each of these components MUST be carefully protected against both external attacks and internal misbehavior by some or all of the operators of the Transparency Service.
For instance, the code for the Registration Policy evaluation and endorsement may be protected by running in a Trusted Execution Environment (TEE).
The Transparency Service may be replicated with a consensus algorithm, such as Practical Byzantine Fault Tolerance (pBFT {{PBFT}}) and may be used to protect against malicious or vulnerable replicas.
Threshold signatures may be use to protect the service key, etc.

Beyond the trusted components, Transparency Services may operate additional endpoints for auditing, for instance to query the history of Signed Statements registered by a given Issuer via a certain Subject.
Implementations of Transparency Services SHOULD avoid using the service identity and extending the Transparency Service in auditing endpoints, except if it is necessary to compute an Append-only Log consistency proofs.
Other evidence to support the correctness and completeness of the audit response MUST be computed from the Append-only Log.

### Service Identity, Remote Attestation, and Keying

Every Transparency Service MUST have a public service identity, associated with public/private key pairs for signing on behalf of the service.
In particular, this identity must be known by Verifiers when validating a Receipt.

This identity MUST be stable for the lifetime of the service, so that all Receipts remain valid and consistent.
The Transparency Service operator MAY use a distributed identifier as their public service identity if they wish to rotate their keys, if the Append-only Log algorithm they use for their Receipt supports it.
Other types of cryptographic identities, such as parameters for non-interactive zero-knowledge proof systems, may also be used in the future.

A Transparency Service MAY provide extra evidence that it is securely implemented and operated, enabling remote authentication of the hardware platforms and/or software TCB that run the Transparency Service.
If present, this additional evidence MUST be recorded in the Append-only Log and presented on demand to Verifiers and Auditors.
Examples for Statements that can improve trustworthy assessments of Transparency Services are RATS Conceptual Messages, such as Evidence, Endorsements, or corresponding Attestation Results (see {{-rats-arch}}).

For example, consider a Transparency Service implemented using a set of replicas, each running within its own hardware-protected trusted execution environments (TEEs).
Each replica MAY provide a recent attestation report for its TEE, binding their hardware platform to the software that runs the Transparency Service, the long-term public key of the service, and the key used by the replica for signing Receipts.
This attestation evidence can be supplemented with Receipts for the software and configuration of the service, as measured in its attestation report.

### Configuration

The Transparency Service records its configuration in the Append-Only Log using Transparent Statements with distinguished media type `application/scitt-configuration`.

The registration policy for statements with the media type suffix (`+<format>` is implementation-specific.
The implementation SHOULD document them, for example defining the Issuers authorized to register configuration Signed Statements.

The Transparency Service is configured by the last Transparent Statement of this type.
The Transparency Service MUST register a Signed Statement that defines its initial configuration before registering any other Signed Statement.
The Transparency Service MAY register an additional Signed Statement that updates its configuration.

The Transparency Service provides an endpoint that returns the Transparent Statement that describes its current configuration.

The configuration `reg_info` SHOULD include a secure version number and a timestamp.

The sample configuration payload uses the CDDL

~~~ cddl
Signature_Algorithms = [ int ]

Registration_Policy = {
  * tstr => any
}

SCITT_Configuration = [
  supported_signature_algs: Signature_Algorithms ; supported algorithms for signing Statement
  ledger_alg: int ; type of verifiable data structure
  service_uri: tstr; base URI of the transparency service, will be the issuer in the receipt CWT claim set
  root_certificates: [ COSE_X509 ]
  supported_apis: [ SCITT_Endpoint ]
  registration_policies : Registration_Policy
]
~~~

### Registration Policies

Authorization is needed prior to registration of Signed Statements to ensure completeness of an audit.
A Transparency Service that registers valid Signed Statement offered by anonymous Issuers would provide limited to no value to Verifiers.
More advanced use case will rely on the Transparency Service performing additional domain-specific checks before a Signed Statement is accepted.
For example, some Transparency Services may validate the non-opaque content (payload) of Signed Statements.

Registration Policies refers to the checks that are performed before a Signed Statement is registered given a set of input values.
This specification leaves the implementation of the Registration Policy to the provider of the Transparency Services and its users.

A provider of a Transparency Service indicates what Registration Policy is used in a given deployment and inform its users about changes to the Registration Policy by issuing and registering configuration statements.

As a minimum, a Transparency Service MUST authenticate the Issuer of the Signed Statement, which requires some form of trust anchor.
As defined in {{RFC6024}}, "A trust anchor represents an authoritative entity via a public key and associated data.
The public key is used to verify digital signatures, and the associated data is used to constrain the types of information for which the trust anchor is authoritative."
The Trust Anchor may be a certificate, a raw public key or other structure, as appropriate.
It can be a non-root certificate when it is a certificate.

### Append-only Log Security Requirements

There are many different candidate verifiable data structures that may be used to implement an Append-only Log, such as chronological Merkle Trees, sparse/indexed Merkle Trees, full blockchains, and many other variants.
The Transparency Service is only required to support concise Receipts (i.e., whose size grows at most logarithmically in the number of entries in the Append-only Log) that can be encoded as a Signed Inclusion Proof.

It is possible to offer multiple signature algorithms for the COSE signature of receipts' Signed Inclusion Proofs, or to change the signing algorithm at later points.
However, the verifiable data structure cannot easily be changed without breaking the consistency of the Append-only Log.
It is possible to maintain separate Registries for each algorithm in parallel but the Transparency Service is then responsible for proving their mutual consistency.

#### Finality

A Transparency Service is append-only.
Once a Signed Statement is registered and becomes a Transparent Statement, it cannot be modified, deleted, or reordered within the Append-only Log.
In particular, once a Receipt is returned for a given Signed Statement, the registered Signed Statement and any preceding entry in the Append-only Log becomes immutable, and the Receipt provides universally-verifiable evidence of this property.

#### Consistency

There is no fork in the Append-only Log.
Everyone with access to its contents sees the same sequence of entries, and can check its consistency with any Receipts they have collected.
Transparency Service implementations MAY provide a mechanism to verify that the state of the Append-only Log, encoded in an old Receipt, is consistent with the current Append-only Log state.

#### Replayability and Auditing

Everyone with access to the Transparency Service can check the correctness of its contents.
In particular:

- the Transparency Service defines and enforces deterministic Registration Policies that can be re-evaluated based solely on the contents of the Append-only Log at the time of Registration, and must then yield the same result
- the ordering of entries, their cryptographic contents, and the Transparency Services' governance may be non-deterministic, but they must be verifiable
- a Transparency Service MAY store evidence about the resolution of identifiers, identity documents, and key material.
- a Transparency Service MAY additionally support verifiability of client authentication and access control

#### Governance and Bootstrapping

Transparency Services MAY document their governance rules and procedures for operating the Transparency Service and updating its code.<br>
Example: relying on Transparent Statements about code updates, secured on its own Append-only Log, or on some auxiliary Transparency Service.<br>

Governance procedures, their auditing, and their transparency are implementation specific.

- Governance may be based on a consortium of members that are jointly responsible for the Transparency Services, or automated based on the contents of an auxiliary governance Transparency Service.
- Governance typically involves additional records in the Append-only Log to enable its auditing.
The Transparency Service may contain both Transparent Statements and governance entries.
- Issuers, Verifiers, and third-party Auditors may review the Transparency Service governance before trusting the service, or on a regular basis.

## Verifying Transparent Statements {#validation}

For a given Transparent Statement, Verifiers take as trusted inputs:

1. the CWT_Claims Issuer (or its resolved key manifest)
1. the collection of Transparent Statements to which this Statement about the Artifact belongs (CWT_Claims Subject)
1. the list of service identities of trusted Transparency Services

When presented with a Transparent Statement for an Artifact, Verifiers verify the CWT_Claims Issuer identity, signature, and Receipt.
They may additionally apply a validation policy based on the protected headers present both in the Envelope, the Receipt, or the Statement itself, which may include security-critical or Artifact-specific details.

Some Verifiers may systematically fetch all Transparent Statements using the CWT_Claims Subject and assess them alongside the Transparent Statement they are verifying to ensure freshness, completeness of evidence, and Non-equivocation.

Some Verifiers may choose to subset the collection of Statements, filtering on the payload type (Protected Header `3`), the CWT (Protected Header `15`) Issuer claim, or other non-opaque properties.

Some Verifiers may systematically resolve Issuer identifiers to fetch the latest corresponding verification keys.
This behavior strictly enforces the revocation of compromised keys.
Once the Issuer has updated its Statement to remove a key identifier, all Signed Statements include the corresponding `kid` will be rejected.

Some Verifiers may decide to skip the identifier-based signature verification, relying on the Transparency Service's Registration Policy and the scrutiny of other Verifiers.
Although this weakens their guarantees against key revocation, or against a corrupt Transparency Services, they can still keep the Receipt and blame the Issuer or the Transparency Services at a later point.

# Signed Statement Issuance, Registration, and Verification

This section details the interoperability requirements for implementers of Signed Statements issuance and validation libraries, and of Transparency Services.

## Signed Statement Envelope

Signed Statements are CBOR encoded {{-CBOR}} and protected by CBOR Object Signing and Encryption (COSE {{-COSE}}).
Signed Statements contain a protected, an unprotected header and a payload.

All Signed Statements MUST include the following protected headers:

- **algorithm** (label: `1`): Asymmetric signature algorithm used by the Issuer of a Signed Statement, as an integer.<br>
  Example: `-35` is the registered algorithm identifier for ECDSA with SHA-384, see [COSE Algorithms Registry](#IANA.cose).
- **Key ID** (label: `4`): Key ID, as a bytestring
- **CWT_Claims** (label: `15` pending {{CWT_CLAIM_COSE}}): A CWT representing the Issuer (`iss`) making the statement, and the Subject (`sub`) to correlate a collection of statements about an Artifact.
  Additional {{CWT_CLAIMS}} MAY be used, while `iss` and `sub` MUST be provided
  - **iss** (CWT_Claim Key `1`): The Identifier of the signer, as a string<br>
    Example: `https://software.vendor.example`
  - **sub** (CWT_Claim Key `2`): The Subject to which the Statement refers, chosen by the Issuer<br>
    Example: `github.com/opensbom-generator/spdx-sbom-generator/releases/tag/v0.0.13`
- **Registration Policy** (label: `TBD`, temporary: `393`): A map containing key/value pairs set by the Issuer which are sealed on Registration and non-opaque to the Transparency Service.
  The key/value pair semantics are specified by the Issuer or are specific to the `CWT_Claims iss` and `CWT_Claims sub` tuple.<br>
  Examples: the sequence number of signed statements on a `CWT_Claims Subject`, Issuer metadata, or a reference to other Transparent Statements (e.g., augments, replaces, new-version, CPE-for)
- **Content type** (label: `3`): The media type of the payload, as a string.<br>
  Example: `application/spdx+json` as the media type of SDPX in JSON encoding

In CDDL {{-CDDL}} notation, a Signed_Statement is defined as follows:

~~~ cddl
Signed_Statement = COSE_Sign1_Tagged

COSE_Sign1_Tagged = #6.18(COSE_Sign1)

COSE_Sign1 = [
  protected   : bstr .cbor Protected_Header,
  unprotected : Unprotected_Header,
  payload     : bstr,
  signature   : bstr
]

CWT_Claims = {
  1 => tstr; iss, the issuer making statements,
  2 => tstr; sub, the subject of the statements,
  * tstr => any
}

Reg_Info = {
  ? "register_by": uint .within (~time),
  ? "sequence_no": uint,
  ? "issuance_ts": uint .within (~time),
  ? "no_replay": null,
  * tstr => any
}

Protected_Header = {
  1   => int             ; algorithm identifier,
  4   => bstr            ; Key ID,
  15  => CWT_Claims      ; CBOR Web Token Claims,
  393 => Reg_Info        ; Registration Policy info,
  3   => tstr            ; payload type
}

Unprotected_Header = {
  ; TBD, Labels are temporary,
  ? 394 => [+ Receipt]
}
~~~

## Creating Signed Statement

There are many types of Statements (such as SBOMs, malware scans, audit reports, policy definitions) that Issuers may want to turn into Signed Statements.
An Issuer must first decide on a suitable format (`3`: payload type) to serialize the Statement payload.
For a software supply chain, payloads describing the software artifacts may include:

- {{COSWID}}
- {{CycloneDX}}
- {{in-toto}}
- {{SPDX-CBOR}}
- {{SPDX-JSON}}
- {{SLSA}}
- {{SWID}}

Once the Statement is serialized with the correct media-type/content-format, an Issuer should fill in the attributes for the Registration Policy information header.
From the Issuer's perspective, using attributes from named policies ensures that the Signed Statement may only be registered on Transparency Services that implement the associated policy.

For instance, if a Signed Statement is frequently updated, and it is important for Verifiers to always consider the latest version, Issuers may use the `sequence_no` or `issuer_ts` attributes.

Once all the Envelope headers are set, an Issuer MUST use a standard COSE implementation to produce an appropriately serialized Signed Statement (the SCITT tag of `COSE_Sign1_Tagged` is outside the scope of COSE, and used to indicate that a signed object is a Signed Statement).

## Registering Signed Statements

The same Signed Statement may be independently registered in multiple Transparency Services.
To register a Signed Statement, the Transparency Service performs the following steps:

1. **Client authentication:** This is implementation-specific and MAY be unrelated to the Issuer identity.
Signed Statements may be registered by a different party than their Issuer.
1. **Issuer Verification:** The Transparency Service MUST perform resolution of the Issuer's identity.
  This step may require that the service retrieves the Issuer ID in real-time, or rely on a cache of recent resolutions.
  For auditing, during Registration, the Transparency Service MUST store evidence of the lookup, including if it was resolved from a cache.
1. **Signature verification:** The Transparency Service MUST verify the signature of the Signed Statement, as described in {{RFC9360}}, using the signature algorithm and verification key of the Issuer.
1. **Signed Statement validation:** The Transparency Service MUST check that the Signed Statement includes the required protected headers listed above.
The Transparency Service MAY verify the Statement payload format, content and other optional properties.
1. **Apply Registration Policy:** For named policies, the Transparency Service MUST check that the required Registration Policy attributes are present in the protected headers and apply the check described in Table 1.
  A Transparency Service MUST reject Signed Statements that contain an attribute used for a named policy that is not enforced by the service.
  Custom Signed Statements are evaluated given the current Transparency Service state and the entire Envelope, and may use information contained in the attributes of named policies.
1. **Register the Signed Statement** to the append-only log
1. **Return the Transparent Statement**, which includes the Receipt
  Details about generating Receipts are described in {{Receipt}}.

The last two steps may be shared between a batch of Signed Statements recorded in the Append-only Log.

A Transparency Service MUST ensure that a Signed Statement is registered before releasing its Receipt, so that it can always back up the Receipt by releasing the corresponding entry (the now Transparent Statement) in the Append-only Log.
Conversely, the Transparency Service MAY re-issue Receipts for the Append-only Log content, for instance after a transient fault during Signed Statement registration.

## Receipts & Transparent Statements  {#Receipt}

When a Signed Statement is registered by a Transparency Service a Receipt becomes available.
When a Receipt is included in a Signed Statement a Transparent Statement is produced.

Receipts are based on Signed Inclusion Proofs as described in COSE Signed Merkle Tree Proofs ({{-COMETRE}}).
Receipts protected headers have additional mandatory fields:

- **scitt-version**: Receipt version number MUST be set to `0` for the current implementation of this document;
- **verifiable-data-structure**: the verifiable data structure used in the inclusion proof of the receipt;
- **registration-info**: The Transparency Service MAY include the Registration policy info header to indicate to
 Verifiers what policies have been applied at the registration of this Statement;
- **kccs**: A CWT Claim Set representing the issuance of the receipt. Only a subset of all CWT claims can be used in a SCITT receipt.
- **crit**: The `crit` header (id: 2) MUST be included and the following headers MUST be marked critical: (`scitt-version`, `verifiable-data-structure`, `kccs`).

Inside Reg_info, the Transparency Service may include the registration time to help Verifiers decide about the trustworthiness of the Transparent Statement.

The registration time is defined as the timestamp at which the Transparency Service has added this Signed Statement to its Append-only Log.

Editor's Note: The WG is discussing if existing CWT claims might better support these design principles.

~~~ cddl
label = int / tstr
value = any

Receipt_Unprotected_Header = {
  &(scitt-inclusion-proof: 396) => bstr .cbor inclusion-proof
}

; Only a subset of valid CWT headers are allowed in SCITT
Receipt_CWT_Claims = {
  1 => tstr,                    ; iss, the issuer signing the receipt (the identifier for the transparency service),
  ? 3 => tstr,                  ; aud, target audience of the receipt
  ? 4 => uint .within (~time),  ; exp, receipt expiration timestamp
  ? 6 => uint .within (~time),  ; iat, receipt issuance timestamp
  * label => value ; label MUST be less than -65536
}

; Statement-agnostic information about registration
; These are authenticated by the receipt signature
Registration_Info = {
  * tstr => any
}

; Statement-specific information about statment registration
; These are authenticated through the inclusion proof of the receipt
Statement_Registration_Info = {
    &(statement-unique-id: 0) => tstr
    &(registration-policy-id: 1) => tstr
    * label => value
}

Receipt_Protected_Header = {
    ; SCITT Receipt Version
    &(scitt-version: 390) => int,

    ; Type of Verifiable Data Structure, e.g. RFC9162_SHA256
    &(verifiable-data-structure: -111) => int,

    ; CBOR Web Tokoken claim set (CCS)
    &(kccs: 15)  => Receipt_CWT_Claims,

    ; Critical headers
    &(crit: 2) => [+ label],

    ; Key ID (optional)
    ? &(kid: 4) => bstr,

    ; X.509 chain (optional)
    ? &(x5chain: 33) => COSE_X509,

    ; Statement-agnostic registration information
    ? &(registration-info: 395) => Registration_Info
}

Receipt_Unprotected_Header = {
    &(statement-registration-info: 396) => Statement_Registration_Info
}

; Please note that receipts cannot carry a payload, ensuring that verifiers
; have to recompute the root from the inclusion proof to verify the signature
Receipt_as_COSE_Sign1 = [
    protected : bstr .cbor Receipt_Protected_Header,
    unprotected : Receipt_Unprotected_Header,
    payload: nil,
    signature : bstr
]

Receipt = #6.18(Receipt_as_COSE_Sign1)

; A Transparent Statement is a Signed Statement
; with one or more Receipts in it's unprotected header.
Transparent_Statement_Unprotected_Header = {
    &(receipts: 394) => [+ Receipt],
    * label => any
}

Transparent_Statement_as_COSE_Sign1 = [
    protected : bstr .cbor Signed_Statement_Protected_Header,
    unprotected : Transparent_Statement_Unprotected_Header,
    payload : bstr / nil,
    signature : bstr
]

Transparent_Statement = #6.18(Transparent_Statement_as_COSE_Sign1)
~~~

Example transparent statement:

### Example

#### Signed Statement

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a4012603...6d706c65',       / Protected                     /
      {                             / Unprotected                   /
        -333: [                     / Receipts (1)                  /
          h'd284586c...4191f9d2'    / Receipt 1                     /
        ]
      },
      h'',                          / Detached payload              /
      h'79ada558...3a28bae4'        / Signature                     /
    ]
)
~~~~

The payload is detached, this is to support very large supply chain artifacts, and to ensure that Transparent Statements can integrate with existing file systems.

The unprotected header can contain multiple receipts.

#### Signed Statement Protected Header

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  3: application/example+json,      / Content type                  /
  4: h'50685f55...50523255',        / Key identifier                /
  15: {                             / CWT Claims                    /
    1: software.vendor.example,     / Issuer                        /
    2: vendor.product.example,      / Subject                       /
  }
}
~~~~

The content type, transparency services might support only certain content types from certain issuers, per their registration policies.

The CWT Claims, transparency services might support only statements about certain artifacts from certain issuers, per their registration policies.

#### Receipt

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a4012604...6d706c65',       / Protected                     /
      {                             / Unprotected                   /
        -222: {                     / Proofs                        /
          -1: [                     / Inclusion proofs (1)          /
            h'83080783...32568964', / Inclusion proof 1             /
          ]
        },
      },
      h'',                          / Detached payload              /
      h'10f6b12a...4191f9d2'        / Signature                     /
    ]
)
~~~~

Notice the unprotected header contains verifiable data structure
proofs, see the protected header for details regarding the specific
verifiable data structure used.

#### Receipt Protected Header

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  4: h'50685f55...50523255',        / Key identifier                /
  -111: 1,                          / Verifiable Data Structure     /
  15: {                             / CWT Claims                    /
    1: transparency.vendor.example, / Issuer                        /
    2: vendor.product.example,      / Subject                       /
  }
}
~~~~

Notice the verifiable data structure used is RFC9162_SHA256 in this case. We know from the COSE Verifiable Data Structure Registry that RFC9162_SHA256 is value 1, and that it supports -1 (inclusion proofs) and -2 (consistency proofs).

#### Inclusion Proof

~~~~ cbor-diag
[                                   / Inclusion proof 1             /
  8,                                / Tree size                     /
  7,                                / Leaf index                    /
  [                                 / Inclusion hashes (3)          /
     h'c561d333...f9850597'         / Intermediate hash 1           /
     h'75f177fd...2e73a8ab'         / Intermediate hash 2           /
     h'0bdaaed3...32568964'         / Intermediate hash 3           /
  ]
]
~~~~

This is a decoded inclusion proof for RFC9162_SHA256, other verifiable data structures might encode inclusion proofs differently.

## Validation of Transparent Statements

The algorithm-specific details of checking inclusion proofs are covered in {{-COMETRE}}.
The pseudo-code for validation of a transparent statement is as follows:

~~~python
let verify_transparent_statement(t) =
  let receipt = t.unprotected.scitt-receipt
  let version = receipt.protected.scitt-version or fail "Missing SCITT Receipt version"
  assert(version == 1)

  let leaf = COSE.serialize(t with .unprotected = {
    334 => receipt.unprotected.statement-registration-info
  })

  let vds = receipt.protected.verifiable-data-structure of fail "Missing verifiable data structure"
  let root = verify_inclusion_proof(vds, receipt.unprotected.scitt-inclusion-proof, leaf)
    or fail "Failed to verify inclusion proof"

  // Statement registration info has been authenticated by the inclusion proof
  receipt.protected.statement-registration-info = receipt.unprotected.statement-registration-info
  return COSE.verify(receipt, detached_payload=root)
~~~

Before checking a Transparent Statement, the Verifier must be configured with one or more identities of trusted Transparency Services.

Verifiers MAY be configured to re-verify the Issuer's Signed Statement locally, but this requires a fresh resolution of the Issuer's verification keys, which MAY fail if the key has been revoked.

Some Verifiers MAY decide to locally re-apply some or all of the Registration Policies, if they have limited trust in the Transparency Services.
In addition, Verifiers MAY apply arbitrary validation policies after the Transparent Statement has been verified and validated.
Such policies may use as input all information in the Envelope, the Receipt, and the Statement payload, as well as any local state.

Verifiers MAY offer options to store or share the Receipt of the Transparent Statement for auditing the Transparency Services in case a dispute arises.

# Federation

**Note**: This topic is still under discussion, see [issue 79](https://github.com/ietf-wg-scitt/draft-ietf-scitt-architecture/issues/79)

Multiple, independently-operated Transparency Services can help secure distributed supply chains, without the need for a single, centralized service trusted by all parties.
For example, multiple Transparency Service instances may be governed and operated by different organizations that are either unaware of the other or do not trust one another.

This may involve registering the same Signed Statements at different Transparency Services, each with their own purpose and Registration Policy.

This may also involve attaching multiple Receipts to the same Signed Statements.

For example, a software producer of a supply chain artifact might rely on multiple independent software producers operating transparency services for their upstream artifacts.
Downstream producers benefit from upstream producers providing higher transparency regarding their artifacts.

# Privacy Considerations

Unless advertised by a Transparency Service, every Issuer must treat Signed Statements it registered (rendering them as Transparent Statements) as public.
In particular, a Signed Statement Envelope and Statement payload MUST NOT carry any private information in plaintext.

# Security Considerations

On its own, verifying a Transparent Statement does not guarantee that its Envelope or contents are trustworthy.
Just that they have been signed by the apparent Issuer and counter-signed by the Transparency Service.
If the Verifier trusts the Issuer, it can infer that an Issuer's Signed Statement was issued with this Envelope and contents, which may be interpreted as the Issuer saying the Artifact is fit for its intended purpose.
If the Verifier trusts the Transparency Service, it can independently infer that the Signed Statement passed the Transparency Service Registration Policy and that has been persisted in the Append-only Log.
Unless advertised in the Transparency Service Registration Policy, the Verifier cannot assume that the ordering of Signed Statements in the Append-only Log matches the ordering of their issuance.

Similarly, the fact that an Issuer can be held accountable for its Transparent Statements does not on its own provide any mitigation or remediation mechanism in case one of these Transparent Statements turned out to be misleading or malicious.
Just that signed evidence will be available to support them.

An Issuer that knows of a changed state of quality for an Artifact, SHOULD Register a new Signed Statement, using the same `15` CWT `iss` and `sub` claims.

Issuers MUST ensure that the Statement payloads in their Signed Statements are correct and unambiguous, for example by avoiding ill-defined or ambiguous formats that may cause Verifiers to interpret the Signed Statement as valid for some other purpose.

Issuers and Transparency Services MUST carefully protect their private signing keys and avoid these keys being used for any purpose not described in this architecture document.
In cases where key re-use is unavoidable, keys MUST NOT sign any other message that may be verified as an Envelope as part of a Signed Statement.

## Threat Model

The document provides a generic threat model for SCITT, describing its residual security properties when some of its actors (identity providers, Issuers, Transparency Services, and Auditors) are corrupt or compromised.

This model may need to be refined to account for specific supply chains and use cases.

### Signed Statement Authentication and Transparency

SCITT primarily supports checking of Signed Statement authenticity, both from the Issuer (authentication) and from the Transparency Service (transparency).
These guarantees are meant to hold for extensive periods of time, possibly decades.

It can never be assumed that some Issuers and some Transparency Services will not be corrupt.

SCITT entities explicitly trust one another on the basis of their long-term identity, which maps to shorter-lived cryptographic credentials.
A Verifier SHOULD validate a Transparent Statement originating from a given Issuer, registered at a given Transparency Service (both identified in the Verifier's local authorization policy) and would not depend on any other Issuer or Transparency Services.

Authorized supply chain actors (Issuers) cannot be stopped from producing Signed Statements including false assertions in their Statement payload (either by mistake or by corruption), but these Issuers can made accountable by ensuring their Signed Statements are systematically registered at a trustworthy Transparency Service.

Similarly, providing strong residual guarantees against faulty/corrupt Transparency Services is a SCITT design goal.
Preventing a Transparency Service from registering Signed Statements that do not meet its stated Registration Policy, or to issue Receipts that are not consistent with their Append-only Log is not possible.
In contrast Transparency Services can be held accountable and they can be called out by any Auditor that replays their Append-only Log against any contested Receipt.
Note that the SCITT Architecture does not require trust in a single centralized Transparency Service.
Different actors may rely on different Transparency Services, each registering a subset of Signed Statements subject to their own policy.

In both cases, the SCITT Architecture provides generic, universally-verifiable cryptographic proof to individually blame Issuers or the Transparency Service.
On one hand, this enables valid actors to detect and disambiguate malicious actors who employ Equivocation with Signed Statements to different entities.
On the other hand, their liability and the resulting damage to their reputation are application specific, and out of scope of the SCITT Architecture.

Verifiers and Auditors need not be trusted by other actors.
In particular, so long as actors maintain proper control of their signing keys and identity infrastructure they cannot "frame" an Issuer or a Transparency Service for Signed Statements they did not issue or register.

#### Append-only Log

If a Transparency Service is honest, then a Transparent Statement including a correct Receipt ensures that the associated Signed Statement passed its Registration Policy and was recorded appropriately.

Conversely, a corrupt Transparency Service may:

1. refuse or delay the Registration of Signed Statements
1. register Signed Statements that do not pass its Registration Policy (e.g., Signed Statement with Issuer identities and signatures that do not verify)
1. issue verifiable Receipts for Signed Statements that do not match its Append-only Log
1. refuse access to its Transparency Service (e.g., to Auditors, possibly after storage loss)

An Auditor granted (partial) access to a Transparency Service and to a collection of disputed Receipts will be able to replay it, detect any invalid Registration (2) or incorrect Receipt in this collection (3), and blame the Transparency Service for them.
This ensures any Verifier that trusts at least one such Auditor that (2, 3) will be blamed to the Transparency Service.

Due to the operational challenge of maintaining a globally consistent Append-only Log, some Transparency Services may provide limited support for historical queries on the Signed Statements they have registered, and accept the risk of being blamed for inconsistent Registration or Issuer Equivocation.

Verifiers and Auditors may also witness (1, 4) but may not be able to collect verifiable evidence for it.

#### Availability of Transparent Statement

Networking and Storage are trusted only for availability.

Auditing may involve access to data beyond what is persisted in the Transparency Services.
For example, the registered Transparency Service may include only the hash of a detailed SBOM, which may limit the scope of auditing.

Resistance to denial-of-service is implementation specific.

Actors may want to independently keep their own record of the Signed Statements they issue, endorse, verify, or audit.

### Confidentiality and Privacy

According to Zero Trust Principles any location in a network is never trusted.
All contents exchanged between actors is protected using secure authenticated channels (e.g., TLS) but may not exclude network traffic analysis.

#### Signed Statements and Their Registration

The Transparency Service is trusted with the confidentiality of the Signed Statements presented for Registration.
Some Transparency Services may publish every Signed Statement in their logs, to facilitate their dissemination and auditing.
Others may just return Receipts to clients that present Singed Statements for Registration, and disclose the Append-only Log only to Auditors trusted with the confidentiality of its contents.

A collection of Signed Statements must not leak information about the contents of other Signed Statements registered on the Transparency Service.

Issuers must carefully review the inclusion of private/confidential materials in their Statements.
For example, Issuers must remove Personally Identifiable Information (PII) as clear text in the statement.
Alternatively, Issuers may include opaque cryptographic statements, such as hashes.

#### Queries to the Transparency Service

The confidentiality of queries is implementation-specific, and generally not guaranteed.
For example, while offline Envelope validation of Signed Statements is private, a Transparency Service may monitor which of its Transparent Statements are being verified from lookups to ensure their freshness.

### Cryptographic Assumptions

SCITT relies on standard cryptographic security for signing schemes (EUF-CMA: for a given key, given the public key and any number of signed messages, an attacker cannot forge a valid signature for any other message) and for Receipts schemes (log collision-resistance: for a given commitment such as a Merkle-tree root, there is a unique log such that any valid path authenticates a Signed Statement in this log.)

The SCITT Architecture supports cryptographic agility.
The actors depend only on the subset of signing and Receipt schemes they trust.
This enables the gradual transition to stronger algorithms, including e.g. post-quantum signature algorithms.

### Transparency Service Clients

Trust in clients that submit Signed Statements for Registration is implementation-specific.
An attacker may attempt to register any Signed Statement it has obtained, at any Transparency Service that accepts them, possibly multiple times and out of order.
This may be mitigated by a Transparency Service that enforces restrictive access control and Registration Policies.

### Identity

The identity resolution mechanism is trusted to associate long-term identifiers with their public signature-verification keys.
Transparency Services and other parties may record identity-resolution evidence to facilitate its auditing.

If one of the credentials of an Issuer gets compromised, the SCITT Architecture still guarantees the authenticity of all Signed Statements signed with this credential that have been registered on a Transparency Service before the compromise.
It is up to the Issuer to notify Transparency Services of credential revocation to stop Verifiers from accepting Signed Statements signed with compromised credentials.
Issuers SHOULD register new Signed Statements indicating the revocation, using the same `15` CWT `iss` and `sub` claims.

The confidentiality of any identity lookup during Signed Statement Registration or Transparent Statement Verification is out of scope.

# IANA Considerations

TBD; {{mybody}}.

## Media Type Registration

This section requests registration of the following media types [@RFC2046] in
the "Media Types" registry [@IANA.MediaTypes] in the manner described
in [@RFC6838].

To indicate that the content is an scitt configuration represented as JSON:

* Type name: application
* Subtype name: scitt-configuration+json
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary; application/scitt-configuration+json values are represented as a JSON Object; UTF-8 encoding SHOULD be employed for the JSON object.
* Security considerations: See the Security Considerations section of [[ this specification ]].
* Interoperability considerations: n/a
* Published specification: [[ this specification ]]
* Applications that use this media type: TBD
* Fragment identifier considerations: n/a
* Additional information:
   * Magic number(s): n/a
   * File extension(s): n/a
   * Macintosh file type code(s): n/a
* Person & email address to contact for further information: TBD
* Intended usage: COMMON
* Restrictions on usage: none
* Author: TBD
* Change Controller: IETF
* Provisional registration?  No

--- back
