#include <Interpreters/TLSLog.h>

#include <Columns/ColumnArray.h>
#include <Common/NetException.h>
#include <Common/DateLUT.h>
#include <IO/ReadBuffer.h>
#include <IO/ReadBufferFromPocoSocket.h>
#include <Core/NamesAndTypes.h>
#include <DataTypes/DataTypeArray.h>
#include <DataTypes/DataTypeDate.h>
#include <DataTypes/DataTypeDateTime.h>
#include <DataTypes/DataTypeDateTime64.h>
#include <DataTypes/DataTypeEnum.h>
#include <DataTypes/DataTypeLowCardinality.h>
#include <DataTypes/DataTypeString.h>
#include <Interpreters/SystemLog.h>
#include <Access/Common/SSLCertificateSubjects.h>
#include <Poco/Net/Socket.h>
#if USE_SSL
#include <Poco/Net/SecureStreamSocketImpl.h>
#endif
#include <cassert>

namespace
{
using namespace DB;

auto eventTime()
{
    const auto finish_time = std::chrono::system_clock::now();

    return std::make_pair(timeInSeconds(finish_time), timeInMicroseconds(finish_time));
}

void fillColumnArray(const Strings & data, IColumn & column)
{
    auto & array = typeid_cast<ColumnArray &>(column);
    size_t size = 0;
    auto & data_col = array.getData();
    for (const auto & name : data)
    {
        data_col.insertData(name.data(), name.size());
        ++size;
    }
    auto & offsets = array.getOffsets();
    offsets.push_back(offsets.back() + size);
}

}

namespace DB
{

TLSLogElement::TLSLogElement(const String &failure_reason_)
    : type(failure_reason_.empty() ? TLSLogElementType::SESSION_SUCCESS : TLSLogElementType::SESSION_FAILURE), failure_reason(failure_reason_)
{
    std::tie(event_time, event_time_microseconds) = eventTime();
}

#if USE_SSL
TLSLogElement::TLSLogElement(const Poco::Net::X509Certificate &tls_certificate, const String &failure_reason_)
    : TLSLogElement(failure_reason_)
{
    time_range = {
        tls_certificate.validFrom().timestamp().epochTime(),
        tls_certificate.expiresOn().timestamp().epochTime()
    };
    using SubjectType = SSLCertificateSubjects::Type;
    SSLCertificateSubjects cert_subjects = extractSSLCertificateSubjects(tls_certificate);
    for (auto subject_type : {SubjectType::CN, SubjectType::SAN})
        for (const auto & subject : cert_subjects.at(subject_type))
            certificate_subjects.push_back(toString(subject_type) + ":" + subject);

    certificate_serial = tls_certificate.serialNumber();
    certificate_issuer = tls_certificate.issuerName();
}
#endif

NamesAndTypesList TLSLogElement::getNamesAndTypes()
{
    auto event_type = std::make_shared<DataTypeEnum8>(
        DataTypeEnum8::Values
        {
            {"failure",           static_cast<Int8>(TLSLogElementType::SESSION_FAILURE)},
            {"success",           static_cast<Int8>(TLSLogElementType::SESSION_SUCCESS)},
        });

    auto lc_string_datatype = std::make_shared<DataTypeLowCardinality>(std::make_shared<DataTypeString>());

    return
    {
        {"type", std::move(event_type)},
        {"event_date", std::make_shared<DataTypeDate>()},
        {"event_time", std::make_shared<DataTypeDateTime>()},
        {"event_time_microseconds", std::make_shared<DataTypeDateTime64>(6)},
        {"certificate_subjects", std::make_shared<DataTypeArray>(lc_string_datatype)},
        {"certificate_not_before", std::make_shared<DataTypeDateTime>()},
        {"certificate_not_after", std::make_shared<DataTypeDateTime>()},
        {"certificate_serial", std::make_shared<DataTypeString>()},
        {"certificate_issuer", std::make_shared<DataTypeString>()},
        {"failure_reason", std::make_shared<DataTypeString>()},
    };
}

ColumnsDescription TLSLogElement::getColumnsDescription()
{
    auto event_type = std::make_shared<DataTypeEnum8>(
    DataTypeEnum8::Values
    {
        {"failure",           static_cast<Int8>(TLSLogElementType::SESSION_FAILURE)},
        {"success",           static_cast<Int8>(TLSLogElementType::SESSION_SUCCESS)},
    });

    auto lc_string_datatype = std::make_shared<DataTypeLowCardinality>(std::make_shared<DataTypeString>());

    return ColumnsDescription
    {
        {"type", std::move(event_type), "Type of event, can either be FAILURE or SUCCESS."},
        {"event_date", std::make_shared<DataTypeDate>(), "Date of the event."},
        {"event_time", std::make_shared<DataTypeDateTime>(), "Time of the event"},
        {"event_time_microseconds", std::make_shared<DataTypeDateTime64>(6), "Time of the event in microseconds."},
        {"certificate_subjects", std::make_shared<DataTypeArray>(lc_string_datatype), "The list of subjects in the certificate."},
        {"certificate_not_before", std::make_shared<DataTypeDateTime>(), "Certificate is valid only after this time."},
        {"certificate_not_after", std::make_shared<DataTypeDateTime>(), "Certificate is not valid after this time."},
        {"certificate_serial", std::make_shared<DataTypeString>(), "Certificate serial number."},
        {"certificate_issuer", std::make_shared<DataTypeString>(), "Certificate issuer."},
        {"failure_reason", std::make_shared<DataTypeString>(), "In case type of event is FAILURE, provides the motive of failure."},
    };
}


void TLSLogElement::appendToBlock(MutableColumns & columns) const
{
    size_t i = 0;

    columns[i++]->insert(type);
    columns[i++]->insert(static_cast<DayNum>(DateLUT::instance().toDayNum(event_time).toUnderType()));
    columns[i++]->insert(event_time);
    columns[i++]->insert(event_time_microseconds);
    fillColumnArray(certificate_subjects, *columns[i++]);
    columns[i++]->insert(time_range.first);
    columns[i++]->insert(time_range.second);
    columns[i++]->insert(certificate_serial);
    columns[i++]->insert(certificate_issuer);
    columns[i++]->insertData(failure_reason.data(), failure_reason.length());
}

void TLSLog::logTLSConnection(ReadBuffer &buffer, Poco::Net::Socket &socket)
{
    (void) buffer; // mark as used
    (void) socket; // mark as used
#if USE_SSL
    auto *secure_socket = dynamic_cast<Poco::Net::SecureStreamSocketImpl *>(socket.impl());
    if (!secure_socket)
        return;

    try {
        buffer.eof();
        if (!secure_socket->havePeerCertificate())
            return;
        add(TLSLogElement(secure_socket->peerCertificate()));
    } catch (DB::NetException &e) {
        if (!secure_socket->havePeerCertificate())
            add(TLSLogElement(secure_socket->peerCertificate(), e.displayText()));
        else
            add(TLSLogElement(e.displayText()));
        throw;
    }
#endif
}

}
